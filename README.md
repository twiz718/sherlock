### Sherlock

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

-----------

## Looking inside the message binary


