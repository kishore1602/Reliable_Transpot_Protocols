/*
 * Programming Assignment 2 - Reliable Transport Protocols
 * Protocol: Go-Back-N (GBN)
 *
 * Sliding window sender, cumulative ACKs.
 * On timeout: retransmit ALL packets in the current window.
 * Receiver: accepts only in-order packets, discards out-of-order.
 * Buffer: vector (random access needed for window retransmission).
 */

#include <vector>
#include <cstring>
#include <cstdio>

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
static int  a_base;         // sequence number of oldest unACKed packet
static int  a_nextseq;      // sequence number of next packet to send
static int  a_winsize;      // window size (from simulator)
static bool a_timer_on;     // is hardware timer running?

// Buffer holds ALL messages ever queued (indexed by seq number offset)
// We keep sent packets for retransmission and unsent ones for sending
static std::vector<struct pkt> a_sent;   // packets in [base, nextseq)
static std::vector<struct msg> a_buf;    // all buffered messages from layer 5
// a_buf[i] corresponds to global sequence number (a_base_start + i)
// We track the "global" index of a_base to index into a_buf
static int a_buf_base;  // index in a_buf of the current window base

// ─────────────────────────────────────────────
// B-side (receiver) state
// ─────────────────────────────────────────────
static int b_expected_seq;  // next expected in-order sequence number
static struct pkt b_last_ack; // last ACK sent (for re-sending on bad packet)

// ─────────────────────────────────────────────
// Helper: checksum = seqnum + acknum + sum of payload bytes
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
// Helper: try to send new packets within window
// ─────────────────────────────────────────────
static void try_send()
{
    // Number of packets currently in-flight
    while ((a_nextseq - a_base) < a_winsize) {
        // Index into a_buf for the next unsent message
        int buf_idx = a_buf_base + (a_nextseq - a_base);
        // Check if we have a buffered message to send
        // a_buf holds ALL messages; buf_idx is relative to initial base
        // We use a global offset: a_nextseq itself as index into a_buf
        // (a_buf grows monotonically; index = a_nextseq)
        if (a_nextseq >= (int)a_buf.size())
            break; // no more messages to send

        struct pkt p = make_data_pkt(a_nextseq, a_buf[a_nextseq].data);
        a_sent.push_back(p);
        tolayer3(A_ENTITY, p);

        if (!a_timer_on) {
            starttimer(A_ENTITY, TIMEOUT);
            a_timer_on = true;
        }
        a_nextseq++;
    }
}

// ═════════════════════════════════════════════
// A-side routines
// ═════════════════════════════════════════════

void A_output(struct msg message)
{
    if ((int)a_buf.size() >= BUFFER_LIMIT) {
        printf("GBN A_output: buffer full, aborting.\n");
        return;
    }
    a_buf.push_back(message);
    try_send();
}

void A_input(struct pkt packet)
{
    if (is_corrupt(packet))
        return;

    // GBN uses cumulative ACKs
    // ACK n means all packets up to and including n are received
    int ack = packet.acknum;

    // Valid ACK must be within [a_base, a_nextseq)
    if (ack < a_base || ack >= a_nextseq)
        return;

    // Slide the window: remove ACKed packets from a_sent
    int advance = ack - a_base + 1;
    a_base = ack + 1;
    // Remove acknowledged packets from front of a_sent
    a_sent.erase(a_sent.begin(), a_sent.begin() + advance);

    if (a_base == a_nextseq) {
        // All outstanding packets ACKed — stop timer
        stoptimer(A_ENTITY);
        a_timer_on = false;
    } else {
        // Restart timer for remaining outstanding packets
        stoptimer(A_ENTITY);
        starttimer(A_ENTITY, TIMEOUT);
        a_timer_on = true;
    }

    try_send(); // send more if window allows
}

void A_timerinterrupt()
{
    // Retransmit ALL packets currently in window
    starttimer(A_ENTITY, TIMEOUT);
    a_timer_on = true;
    for (int i = 0; i < (int)a_sent.size(); i++) {
        tolayer3(A_ENTITY, a_sent[i]);
    }
}

void A_init()
{
    a_winsize  = getwinsize();
    a_base     = 0;
    a_nextseq  = 0;
    a_timer_on = false;
    a_buf_base = 0;
    a_buf.clear();
    a_sent.clear();
}

// ═════════════════════════════════════════════
// B-side routines
// ═════════════════════════════════════════════

void B_input(struct pkt packet)
{
    if (is_corrupt(packet)) {
        // Re-send last ACK
        tolayer3(B_ENTITY, b_last_ack);
        return;
    }

    if (packet.seqnum == b_expected_seq) {
        // In-order packet — deliver and ACK
        tolayer5(B_ENTITY, packet.payload);
        b_last_ack = make_ack(b_expected_seq);
        tolayer3(B_ENTITY, b_last_ack);
        b_expected_seq++;
    } else {
        // Out-of-order: discard and re-ACK last good packet
        tolayer3(B_ENTITY, b_last_ack);
    }
}

void B_timerinterrupt() { /* not used in GBN */ }

void B_init()
{
    b_expected_seq = 0;
    // Initial last ACK: ACK -1 (nothing received yet)
    b_last_ack = make_ack(-1);
}
