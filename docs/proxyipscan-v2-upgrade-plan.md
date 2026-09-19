# ProxyIP Scanner V2 Upgrade Plan

## Goal

Keep the existing scanner workflow stable and evolve the system into a long-running proxy quality pool.

## Core changes

### 1. Incremental candidate processing

Old model:

- refresh sources
- rescan large candidate pool repeatedly

V2 model:

- new IP enters candidate queue
- only new or expired IPs are verified
- successful nodes enter usable proxy pool
- historical quality data is retained

### 2. Quality scoring

Each proxy receives an internal score (0-100):

- availability stability
- latency
- throughput
- Cloudflare/edge characteristics
- ASN/network quality
- freshness
- failure history

Score is used for ranking, promotion and cleanup.

### 3. Lifecycle management

States:

NEW -> VERIFYING -> ACTIVE -> AGING -> RETIRED

Rules:

- high score nodes stay longer
- repeated failures reduce score
- expired low quality nodes are removed first
- storage keeps metadata, not unlimited raw scan history

### 4. Source expansion

Future background collectors:

- GitHub public sources
- public proxy lists
- ASN based discovery
- DNS/domain historical discovery

Source collectors should only feed candidates; scoring decides promotion.

### 5. Resource protection

Design requirements:

- streaming processing
- bounded queues
- batch verification
- release temporary scan data after completion
- avoid loading complete world IP datasets into memory

This document describes the target architecture and does not replace current runtime behaviour until integration tests are completed.
