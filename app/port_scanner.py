import os, subprocess, datetime, xml.etree.ElementTree as ET, json, csv

class PortScanner:
    def __init__(self, artifact_root="data/artifacts"):
        self.root = artifact_root
        os.makedirs(self.root, exist_ok=True)

    def _nmap_cmd(self, ip, tcp_ports=None, udp_ports=None, version=False, timing=None, host_timeout=None):
        cmd = ["nmap", "-n", "-Pn", "-oX", "-"]
        if tcp_ports:
            cmd += ["-sS", "-p", tcp_ports]
        if udp_ports:
            cmd += ["-sU", "-p", udp_ports]
        if version:
            cmd += ["-sV"]
        if timing:
            # timing like 'T3', 'T4'
            if timing.startswith('T'):
                cmd += [f"-T{timing[1:]}" ]
        if host_timeout:
            cmd += ["--host-timeout", str(host_timeout)]
        cmd += [ip]
        return cmd

    def _parse_xml(self, xml_text):
        open_tcp, open_udp = [], []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return open_tcp, open_udp
        for host in root.findall("host"):
            for port in host.findall("./ports/port"):
                proto = port.attrib.get("protocol")
                portid = port.attrib.get("portid")
                state_el = port.find("state")
                if not state_el or state_el.attrib.get("state") != "open":
                    continue
                service_el = port.find("service")
                service = service_el.attrib.get("name") if service_el is not None else ""
                product = service_el.attrib.get("product") if service_el is not None else ""
                version = service_el.attrib.get("version") if service_el is not None else ""
                rec = {"port": int(portid), "service": service, "product": product, "version": version}
                if proto == "tcp":
                    open_tcp.append(rec)
                elif proto == "udp":
                    open_udp.append(rec)
        return sorted(open_tcp, key=lambda x: x["port"]), sorted(open_udp, key=lambda x: x["port"])

    def scan_host(self, ip, tcp_ports=None, udp_ports=None, version=False, timing="T4", host_timeout="90s"):
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        outdir = os.path.join(self.root, f"ports_{ip.replace(':','_').replace('.','_')}_{ts}")
        os.makedirs(outdir, exist_ok=True)

        cmd = self._nmap_cmd(ip, tcp_ports=tcp_ports, udp_ports=udp_ports, version=version, timing=timing, host_timeout=host_timeout)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        out = proc.communicate()[0]
        rc = proc.returncode

        xml_path = os.path.join(outdir, "nmap.xml")
        with open(xml_path, "w") as f:
            f.write(out)

        open_tcp, open_udp = self._parse_xml(out)

        # save JSON
        summary = {
            "ip": ip, "tcp_ports": tcp_ports, "udp_ports": udp_ports, "version_probe": version,
            "open_tcp": open_tcp, "open_udp": open_udp, "return_code": rc
        }
        with open(os.path.join(outdir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=2)

        # CSV
        with open(os.path.join(outdir, "ports.csv"), "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["protocol","port","service","product","version"])
            for r in open_tcp:
                w.writerow(["tcp", r["port"], r["service"], r["product"], r["version"]])
            for r in open_udp:
                w.writerow(["udp", r["port"], r["service"], r["product"], r["version"]])

        # HTML report
        html = ["<!doctype html><html><head><meta charset='utf-8'><title>Port Report — "+ip+"</title>",
                "<link rel='stylesheet' href='../static/app.css'></head><body>",
                f"<header><h1>Port Report — {ip}</h1></header>"]
        def table(title, rows, proto):
            if not rows:
                return f"<h2>{title}</h2><p>No open {proto.upper()} ports found.</p>"
            s = [f"<h2>{title}</h2><table><thead><tr><th>Port</th><th>Service</th><th>Product</th><th>Version</th></tr></thead><tbody>"]
            for r in rows:
                s.append(f"<tr><td>{r['port']}</td><td>{r['service']}</td><td>{r['product']}</td><td>{r['version']}</td></tr>")
            s.append("</tbody></table>")
            return "".join(s)
        html.append(table("Open TCP Ports", open_tcp, "tcp"))
        html.append(table("Open UDP Ports", open_udp, "udp"))
        html.append("</body></html>")
        with open(os.path.join(outdir, "report.html"), "w") as f:
            f.write("\n".join(html))

        return outdir, open_tcp, open_udp, rc
