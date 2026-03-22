/*
 * Programming Assignment 2 - Reliable Transport Protocols
 * Protocol: Alternating-Bit (ABT / rdt3.0)
 *
 * Implements stop-and-wait reliable data transfer from A to B.
 * Uses sequence numbers 0 and 1 alternately.
 * Buffer: queue (only one packet in transit at a time).
 */

#include <queue>
#include <cstring>
#include <cstdio>

// ─────────────────────────────────────────────
// Simulator-provided declarations
// ─────────────────────────────────────────────
extern "C" {
    void starttimer(int entity, float increment);
    void stoptimer(int entity);
    void tolayer3(int entity, struct pkt packet);
    void tolayer5(int entity, char *datasent);
    int  getwinsize();
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
static int          a_seq;          // current sequence number (0 or 1)
static bool         a_waiting;      // true when a packet is in transit
static struct pkt   a_last_pkt;    // last sent packet (for retransmission)
static std::queue<struct msg> a_buffer; // buffered messages from Layer 5

// ─────────────────────────────────────────────
// B-side (receiver) state
// ─────────────────────────────────────────────
static int b_expected_seq; // next expected sequence number at B

// ─────────────────────────────────────────────
// Helper: compute checksum
// checksum = seqnum + acknum + sum of payload bytes
// ─────────────────────────────────────────────
static int compute_checksum(const struct pkt &p)
{
    int sum = p.seqnum + p.acknum;
    for (int i = 0; i < 20; i++)
        sum += (unsigned char)p.payload[i];
    return sum;
}

// ─────────────────────────────────────────────
// Helper: build a data packet
// ─────────────────────────────────────────────
static struct pkt make_pkt(int seq, const char *data)
{
    struct pkt p;
    p.seqnum = seq;
    p.acknum = 0;
    memcpy(p.payload, data, 20);
    p.checksum = compute_checksum(p);
    return p;
}

// ─────────────────────────────────────────────
// Helper: build an ACK packet
// ─────────────────────────────────────────────
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
// Helper: is packet corrupt?
// ─────────────────────────────────────────────
static bool is_corrupt(const struct pkt &p)
{
    return compute_checksum(p) != p.checksum;
}

// ─────────────────────────────────────────────
// Helper: send the front of the buffer
// ─────────────────────────────────────────────
static void send_next()
{
    if (a_buffer.empty() || a_waiting)
        return;

    struct msg m = a_buffer.front();
    a_buffer.pop();

    a_last_pkt = make_pkt(a_seq, m.data);
    tolayer3(A_ENTITY, a_last_pkt);
    starttimer(A_ENTITY, TIMEOUT);
    a_waiting = true;
}

// ═════════════════════════════════════════════
// A-side routines
// ═════════════════════════════════════════════

void A_output(struct msg message)
{
    if ((int)a_buffer.size() >= BUFFER_LIMIT) {
        printf("ABT A_output: buffer full, dropping message.\n");
        return;
    }
    a_buffer.push(message);
    send_next();            // will no-op if already waiting
}

void A_input(struct pkt packet)
{
    // Ignore corrupt packets or wrong ACK
    if (is_corrupt(packet) || packet.acknum != a_seq)
        return;

    // Correct ACK received
    stoptimer(A_ENTITY);
    a_waiting = false;
    a_seq = 1 - a_seq;     // flip sequence number

    send_next();            // send next buffered message if any
}

void A_timerinterrupt()
{
    // Retransmit last packet
    tolayer3(A_ENTITY, a_last_pkt);
    starttimer(A_ENTITY, TIMEOUT);
}

void A_init()
{
    a_seq     = 0;
    a_waiting = false;
    memset(&a_last_pkt, 0, sizeof(a_last_pkt));
    while (!a_buffer.empty()) a_buffer.pop();
}

// ═════════════════════════════════════════════
// B-side routines
// ═════════════════════════════════════════════

void B_input(struct pkt packet)
{
    if (is_corrupt(packet)) {
        // Send ACK for the last correctly received packet
        struct pkt ack = make_ack(1 - b_expected_seq);
        tolayer3(B_ENTITY, ack);
        return;
    }

    if (packet.seqnum == b_expected_seq) {
        // Correct in-order packet
        tolayer5(B_ENTITY, packet.payload);
        struct pkt ack = make_ack(b_expected_seq);
        tolayer3(B_ENTITY, ack);
        b_expected_seq = 1 - b_expected_seq;
    } else {
        // Duplicate: re-ACK the previous sequence number
        struct pkt ack = make_ack(1 - b_expected_seq);
        tolayer3(B_ENTITY, ack);
    }
}

void B_timerinterrupt() { /* not used in ABT */ }

void B_init()
{
    b_expected_seq = 0;
}
