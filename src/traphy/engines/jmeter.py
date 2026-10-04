"""The JMeter engine - declared, not yet implemented.

Where it fits: the Scapy and TRex engines answer "does this device forward
frames, and at what rate does it stop". JMeter answers a different question -
"does the service behind it hold up under N clients doing real requests" - and
that question comes up on the same benches, against the same targets, usually
right after the L2-L4 answer is in. Same host, same SSH transport, same run
archive; only the artefact and the counters differ.

What it will need, and why it does not reuse the packet model:

* **A different unit of load.** Not frames and pps, but thread groups: number
  of threads, ramp-up, loop count or duration, and a request - method, URL,
  headers, body. :class:`~traphy.models.Packet` has nothing to say about any
  of that, so this engine wants its own small model beside it rather than a
  layer stretched over it.
* **A ``.jmx`` plan, not a script.** The artefact is XML - the same shape the
  GUI writes - so a plan built here can be opened in JMeter afterwards. That is
  the point: it has to be a real plan, not something only this tool can run.
* **A different invocation.** ``jmeter -n -t plan.jmx -l results.jtl``, needing
  a JVM on the host. Progress comes from the summariser on stdout or from the
  ``.jtl`` as it is written, so the runner's ``@traphy`` event stream has to be
  produced by parsing JMeter's own output rather than by code we generate.
* **Different counters.** Requests, errors, latency percentiles and throughput
  - not tx, rx and loss. :class:`~traphy.runner.RunResult` would grow a second
  shape, and the honesty rule stays: a percentile from a run that could not
  reach its target rate describes the load generator, not the service.

Selecting it is allowed; every path that would touch the wire refuses with the
reason rather than half-working.
"""

from __future__ import annotations

from traphy.engines.base import Declared
from traphy.probe import HostInfo


class JMeterEngine(Declared):
    key = "jmeter"
    title = "JMeter"
    hint = "L7: потоки, запросы, задержки"
    layers = "L7"
    ready = False
    status = "ещё не реализован"
    file_suffix = ".jmx"
    # Порт у этого движка - не карта, а адрес службы: нагрузку задают потоки и
    # запрос, а через какой интерфейс уйдёт TCP, решает маршрутизация. Пока
    # стояло умолчание, форма цели спрашивала имена TX/RX и обещала sudo для
    # сырого сокета, который JMeter не открывает никогда.
    uses_ifaces = False

    def blockers(self, host: HostInfo) -> list[str]:
        out = [f"движок JMeter {self.status}"]
        if not host.has_java:
            out.append("на цели нет java - JMeter без JVM не запустится")
        if not host.has_jmeter:
            out.append("на цели не найден jmeter в PATH")
        return out
