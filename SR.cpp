/*
 * Programming Assignment 2 - Reliable Transport Protocols
 * Protocol: Selective-Repeat (SR)
 *
 * Sliding window on BOTH sender and receiver.
 * Only the lost/corrupted packet is retransmitted (not the whole window).
 * Receiver buffers out-of-order packets and ACKs each one individually.
 *
 * Software timers:
 *   Each in-flight packet has its own logical timer stored in a hash map
 *   (key = seqnum, value = expiration time). The single hardware timer is
 *   always set to fire at the earliest expiration time among all active
 *   software timers. When it fires, all expired software timers are
 *   processed (packets retransmitted) and the hardware timer is reset to
 *   the next earliest expiration.
 *
 * Buffers:
 *   Sender : unordered_map<int,pkt>  — in-flight packets keyed by seqnum
 *   Receiver: unordered_map<int,pkt> — out-of-order packets keyed by seqnum
 */

#include <unordered_map>
#include <vector>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <climits>

// ─────────────────────────────────────────────
// Simulator-provided declarations
// ─────────────────────────────────────────────
extern "C" {
    void  starttimer(int entity, float increment);
    void  stoptimer(int entity);
    void  tolayer3(int entity, struct pkt packet);
    void  tolayer5(int entity, char *datasent);
    int   getwinsize();
    float get_sim_time();
}

struct msg { char data[20]; };
struct pkt { int seqnum; int acknum; int checksum; char payload[20]; };

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────
static const float TIMEOUT      = 11.0f;
static const int   A_ENTITY     = 0;
static const int   B_ENTITY     = 1;
static const int   BUFFER_LIMIT = 1000;

// ─────────────────────────────────────────────
// A-side (sender) state
// ─────────────────────────────────────────────
static int  a_winsize;          // window size from simulator
static int  a_base;             // seq number of oldest unACKed packet
static int  a_nextseq;          // seq number of next packet to send

// All messages buffered from Layer 5 (index == sequence number)
static std::vector<struct msg> a_msgbuf;

// In-flight packets: seqnum -> pkt  (for retransmission)
static std::unordered_map<int, struct pkt> a_inflight;

// Software timers: seqnum -> expiration_time
static std::unordered_map<int, float> a_timers;

static bool a_hw_timer_on;  // is hardware timer currently running?

// ─────────────────────────────────────────────
// B-side (receiver) state
// ─────────────────────────────────────────────
static int  b_winsize;          // same window size
static int  b_base;             // seq number of oldest expected packet

// Out-of-order received packets: seqnum -> pkt
static std::unordered_map<int, struct pkt> b_received;

// ─────────────────────────────────────────────
// Helpers: checksum
// ─────────────────────────────────────────────
static int compute_checksum(const struct pkt &p)
{
    int sum = p.seqnum + p.acknum;
    for (int i = 0; i < 20; i++)
        sum += (unsigned char)p.payload[i];
    return sum;
}

static bool is_corrupt(const struct pkt &p)
{
    return compute_checksum(p) != p.checksum;
}

static struct pkt make_data_pkt(int seq, const char *data)
{
    struct pkt p;
    p.seqnum = seq;
    p.acknum = 0;
    memcpy(p.payload, data, 20);
    p.checksum = compute_checksum(p);
    return p;
}

static struct pkt make_ack(int ack)
{
    struct pkt p;
    p.seqnum = 0;
    p.acknum = ack;
    memset(p.payload, 0, 20);
    p.checksum = compute_checksum(p);
    return p;
}

// ─────────────────────────────────────────────
// Software timer helpers
// ─────────────────────────────────────────────

// Find the minimum expiration time among all active software timers.
// Returns -1.0f if no timers are active.
static float earliest_expiry()
{
    if (a_timers.empty()) return -1.0f;
    float earliest = -1.0f;
    for (auto &kv : a_timers) {
        if (earliest < 0.0f || kv.second < earliest)
            earliest = kv.second;
    }
    return earliest;
}

// Reset the hardware timer to fire at the earliest software timer expiry.
static void reset_hw_timer()
{
    float exp = earliest_expiry();
    if (exp < 0.0f) {
        // No active software timers
        if (a_hw_timer_on) {
            stoptimer(A_ENTITY);
            a_hw_timer_on = false;
        }
        return;
    }
    float now  = get_sim_time();
    float left = exp - now;
    if (left < 0.001f) left = 0.001f; // guard against negative/zero
    if (a_hw_timer_on) stoptimer(A_ENTITY);
    starttimer(A_ENTITY, left);
    a_hw_timer_on = true;
}

// Start a software timer for packet with sequence number seq.
static void start_sw_timer(int seq)
{
    float expiry = get_sim_time() + TIMEOUT;
    a_timers[seq] = expiry;
    // If this is the new earliest, reset hardware timer
    float earliest = earliest_expiry();
    if (earliest >= 0.0f && a_timers[seq] <= earliest + 0.0001f)
        reset_hw_timer();
    else if (!a_hw_timer_on)
        reset_hw_timer();
}

// Stop the software timer for packet seq (e.g., after receiving its ACK).
static void stop_sw_timer(int seq)
{
    auto it = a_timers.find(seq);
    if (it == a_timers.end()) return;

    bool was_earliest = true; // check if we removed the earliest
    float removed_exp = it->second;
    a_timers.erase(it);

    // Check if removed timer was the earliest
    float new_earliest = earliest_expiry();
    if (new_earliest < 0.0f || removed_exp <= new_earliest + 0.0001f)
        reset_hw_timer(); // need to update hardware timer
}

// ─────────────────────────────────────────────
// Sender helper: send a packet and start its software timer
// ─────────────────────────────────────────────
static void send_pkt(int seq)
{
    struct pkt p = make_data_pkt(seq, a_msgbuf[seq].data);
    a_inflight[seq] = p;
    tolayer3(A_ENTITY, p);
    start_sw_timer(seq);
}

// Try to send new packets within the window
static void try_send()
{
    while ((a_nextseq - a_base) < a_winsize &&
           a_nextseq < (int)a_msgbuf.size()) {
        send_pkt(a_nextseq);
        a_nextseq++;
    }
}

// ═════════════════════════════════════════════
// A-side routines
// ═════════════════════════════════════════════

void A_output(struct msg message)
{
    if ((int)a_msgbuf.size() >= BUFFER_LIMIT) {
        printf("SR A_output: buffer full, aborting.\n");
        return;
    }
    a_msgbuf.push_back(message);
    try_send();
}

void A_input(struct pkt packet)
{
    if (is_corrupt(packet)) return;

    int ack = packet.acknum;

    // ACK must be within the sender window [a_base, a_nextseq)
    if (ack < a_base || ack >= a_nextseq) return;

    // Mark this packet as ACKed: remove from in-flight and stop its timer
    if (a_inflight.count(ack)) {
        a_inflight.erase(ack);
        stop_sw_timer(ack);
    }

    // Slide window base forward over consecutive ACKed packets
    while (a_base < a_nextseq && a_inflight.find(a_base) == a_inflight.end()) {
        a_base++;
    }

    try_send(); // may open window for new sends
}

void A_timerinterrupt()
{
    // Hardware timer fired: find all expired software timers and retransmit
    float now = get_sim_time();

    // Collect expired sequence numbers first (avoid modifying map while iterating)
    std::vector<int> expired;
    for (auto &kv : a_timers) {
        if (kv.second <= now + 0.001f)
            expired.push_back(kv.first);
    }

    for (int seq : expired) {
        // Reset the software timer (extend expiry)
        a_timers[seq] = now + TIMEOUT;
        // Retransmit
        if (a_inflight.count(seq)) {
            tolayer3(A_ENTITY, a_inflight[seq]);
        }
    }

    // Reset hardware timer to next earliest expiry
    reset_hw_timer();
}

void A_init()
{
    a_winsize     = getwinsize();
    a_base        = 0;
    a_nextseq     = 0;
    a_hw_timer_on = false;
    a_msgbuf.clear();
    a_inflight.clear();
    a_timers.clear();
}

// ═════════════════════════════════════════════
// B-side routines
// ═════════════════════════════════════════════

void B_input(struct pkt packet)
{
    if (is_corrupt(packet)) return; // drop silently; sender will retransmit

    int seq = packet.seqnum;

    // Check if seq is within receiver window [b_base, b_base + b_winsize)
    if (seq >= b_base && seq < b_base + b_winsize) {

        // Always ACK any valid packet inside the window
        struct pkt ack = make_ack(seq);
        tolayer3(B_ENTITY, ack);

        if (seq == b_base) {
            // In-order: deliver immediately, then deliver any buffered consecutive
            tolayer5(B_ENTITY, packet.payload);
            b_base++;

            // Deliver any already-buffered consecutive packets
            while (b_received.count(b_base)) {
                tolayer5(B_ENTITY, b_received[b_base].payload);
                b_received.erase(b_base);
                b_base++;
            }
        } else if (!b_received.count(seq)) {
            // Out-of-order but within window: buffer if not already received
            b_received[seq] = packet;
        }
        // If already received (duplicate within window), ACK was already sent above

    } else if (seq >= b_base - b_winsize && seq < b_base) {
        // Packet is in the previous window — sender may not have gotten our ACK
        // Re-send ACK for it
        struct pkt ack = make_ack(seq);
        tolayer3(B_ENTITY, ack);
    }
    // Otherwise: completely outside any valid range — drop silently
}

void B_timerinterrupt() { /* not used in SR receiver */ }

void B_init()
{
    b_winsize = getwinsize();
    b_base    = 0;
    b_received.clear();
}
