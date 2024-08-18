## What is Sherlock?

Sherlock is meant to a be a proof of concept project that showcases the possibilites of libpcap in conjunction with [miekg/dns](https://github.com/miekg/dns) and [google/gopacket](https://github.com/google/gopacket).

Sherlock is able to capture live DNS traffic on a specified interface, port & protocol and then save the questions & answers into json & bin files.

Example output after capturing a DNS request & response for `A` record of `cat.com`:

```
Live capturing on INTERFACE [lo] PROTOCOL [udp] PORT[15300]
SRC IP [127.0.0.1] SRC PORT [60038] DST IP [127.0.0.1] DST PORT [15300] LEN [33] CHECKSUM [65076]
Processing Question with msg ID [QUESTION_127.0.0.1_60038_A_cat.com_1723941648]
  Wrote 295 bytes to QUESTION_127.0.0.1_60038_A_cat.com_1723941648.json
  Wrote 25 bytes to QUESTION_127.0.0.1_60038_A_cat.com_1723941648.bin
SRC IP [127.0.0.1] SRC PORT [15300] DST IP [127.0.0.1] DST PORT [60038] LEN [56] CHECKSUM [65099]
Processing Answer with msg ID [ANSWER_127.0.0.1_60038_A_cat.com_1723941648]
  Wrote 380 bytes to ANSWER_127.0.0.1_60038_A_cat.com_1723941648.json
  Wrote 48 bytes to ANSWER_127.0.0.1_60038_A_cat.com_1723941648.bin
```

The request was made from my local dev env the source ip is 127.0.0.1 to 127.0.0.1 which is also running my dummy DNS server running on port 15300.

```
-rw-r--r-- 1 root root  48 Aug 17 19:40 ANSWER_127.0.0.1_60038_A_cat.com_1723941648.bin
-rw-r--r-- 1 root root 380 Aug 17 19:40 ANSWER_127.0.0.1_60038_A_cat.com_1723941648.json
-rw-r--r-- 1 root root  25 Aug 17 19:40 QUESTION_127.0.0.1_60038_A_cat.com_1723941648.bin
-rw-r--r-- 1 root root 295 Aug 17 19:40 QUESTION_127.0.0.1_60038_A_cat.com_1723941648.json
```

The files are named according to whether they are a DNS QUESTION or a DNS ANSWER. They contain the IP of the requester, the port the requester was connecting from, the type of DNS record requested, the fqdn & the unix timestamp.

Contents of `QUESTION_127.0.0.1_60038_A_cat.com_1723941648.json` above:

```
$ cat QUESTION_127.0.0.1_60038_A_cat.com_1723941648.json|jq .
{
  "Id": 4823,
  "Response": false,
  "Opcode": 0,
  "Authoritative": false,
  "Truncated": false,
  "RecursionDesired": true,
  "RecursionAvailable": false,
  "Zero": false,
  "AuthenticatedData": false,
  "CheckingDisabled": false,
  "Rcode": 0,
  "Question": [
    {
      "Name": "cat.com.",
      "Qtype": 1,
      "Qclass": 1
    }
  ],
  "Answer": null,
  "Ns": null,
  "Extra": null
}
```

Contents of `ANSWER_127.0.0.1_60038_A_cat.com_1723941648.json` above:

```
$ cat ANSWER_127.0.0.1_60038_A_cat.com_1723941648.json | jq .
{
  "Id": 4823,
  "Response": true,
  "Opcode": 0,
  "Authoritative": false,
  "Truncated": false,
  "RecursionDesired": true,
  "RecursionAvailable": true,
  "Zero": false,
  "AuthenticatedData": false,
  "CheckingDisabled": false,
  "Rcode": 0,
  "Question": [
    {
      "Name": "cat.com.",
      "Qtype": 1,
      "Qclass": 1
    }
  ],
  "Answer": [
    {
      "Hdr": {
        "Name": "cat.com.",
        "Rrtype": 1,
        "Class": 1,
        "Ttl": 7,
        "Rdlength": 4
      },
      "A": "104.68.255.35"
    }
  ],
  "Ns": null,
  "Extra": null
}
```

---

## Looking inside the message binary

As per the [rfc1035](https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1), the message format is as follows:

```
The header contains the following fields:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

ID              A 16 bit identifier assigned by the program that
                generates any kind of query.  This identifier is copied
                the corresponding reply and can be used by the requester
                to match up replies to outstanding queries.

---

The question section is used to carry the "question" in most queries,
i.e., the parameters that define what is being asked.  The section
contains QDCOUNT (usually 1) entries, each of the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```

Here is an example of an `A` request for `slow.com`:

```
xxd -u -g1 QUESTION_127.0.0.1_msgid-60311_port-41685_A_slow.com_1723999423.bin
00000000: EB 97 01 00 00 01 00 00 00 00 00 00 04 73 6C 6F  .............slo
00000010: 77 03 63 6F 6D 00 00 01 00 01                    w.com.....
```

Since we know the `msg id` is the first `16` bits of the data, we can figure out it's value from the above hex output via `xxd`.

Since each byte contains 8 bits, we need the first two bytes only. Let's retrieve them:

```
xxd -p -u -l 2 QUESTION_127.0.0.1_msgid-60311_port-41685_A_slow.com_1723999423.bin
EB97
```

Now we can convert them to decimal to retrieve our `msg id`. `EB97` (hex) -> `60311` (decimal)
One-liner:
```
echo $((0x$(xxd -p -u -l 2 QUESTION_127.0.0.1_msgid-60311_port-41685_A_slow.com_1723999423.bin)))
60311
```

or via `bc`:

```
echo "ibase=16; EB97" | bc
60311
```

Let's confirming via our JSON file for the same question:
```
cat QUESTION_127.0.0.1_msgid-60311_port-41685_A_slow.com_1723999423.json|jq .
{
  "Id": 60311,
  "Response": false,
  "Opcode": 0,
  "Authoritative": false,
  "Truncated": false,
  "RecursionDesired": true,
  "RecursionAvailable": false,
  "Zero": false,
  "AuthenticatedData": false,
  "CheckingDisabled": false,
  "Rcode": 0,
  "Question": [
    {
      "Name": "slow.com.",
      "Qtype": 1,
      "Qclass": 1
    }
  ],
  "Answer": null,
  "Ns": null,
  "Extra": null
}
```

The confirmation:
```
cat QUESTION_127.0.0.1_msgid-60311_port-41685_A_slow.com_1723999423.json |jq .Id
60311
```