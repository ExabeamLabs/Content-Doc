#### Parser Content
```Java
{
Name = bro-conn
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "epoch_sec"
  Conditions = [ "/conn.log" ]
  Fields = [
      """({time}\d{10})\.\d{6}\t({uid}[^\t]{1,2000})\t(({id_orig_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000})\t(({id_orig_p}\d{1,100}?)|[^\t]{1,2000})\t(({id_resp_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000})\t(({id_resp_p}\d{1,100}?)|[^\t]{1,2000})\t({proto}[^\t]{1,2000})\t({service}[^\t]{1,2000})\t({duration}[^\t]{1,2000})\t({orig_bytes}[^\t]{1,2000})\t({resp_bytes}[^\t]{1,2000})\t({conn_state}[^\t]{1,2000})\t({local_orig}[^\t]{1,2000})\t({local_resp}[^\t]{1,2000})\t({missed_bytes}[^\t]{1,2000})\t({history}[^\t]{1,2000})\t({orig_pkts}[^\t]{1,2000})\t({orig_ip_bytes}[^\t]{1,2000})\t({resp_pkts}[^\t]{1,2000})\t({resp_ip_bytes}[^\t]{1,2000})\t({tunnel_parents}[^\s]{1,2000})\s{0,100}"""
      """\d{10}\.\d{6}\t([^\t]{1,2000}\t){20}({orig_cc}[^\t]{1,2000})\t({resp_cc}[^\t]{1,2000})\t({sensorname}[^\s]{1,2000})\s{0,100}"""
  ]
  DupFields = [ "id_orig_h->src_ip", "id_orig_p->src_port", "id_resp_h->dest_ip", "id_resp_p->dest_port", "sensorname->src_interface", "orig_ip_bytes->bytes_out", "resp_ip_bytes->bytes_in" ]
}
```