#### Parser Content
```Java
{
Name = bro-conn
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "network-connection"
  TimeFormat = "epoch_sec"
  Conditions = [ "/conn.log" ]
  Fields = [
      """({time}\d{10})\.\d{6}\t({uid}[^\t]+)\t(({id_orig_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+)\t(({id_orig_p}\d+?)|[^\t]+)\t(({id_resp_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+)\t(({id_resp_p}\d+?)|[^\t]+)\t({proto}[^\t]+)\t({service}[^\t]+)\t({duration}[^\t]+)\t({orig_bytes}[^\t]+)\t({resp_bytes}[^\t]+)\t({conn_state}[^\t]+)\t({local_orig}[^\t]+)\t({local_resp}[^\t]+)\t({missed_bytes}[^\t]+)\t({history}[^\t]+)\t({orig_pkts}[^\t]+)\t({orig_ip_bytes}[^\t]+)\t({resp_pkts}[^\t]+)\t({resp_ip_bytes}[^\t]+)\t({tunnel_parents}[^\s]+)\s*"""
      """\d{10}\.\d{6}\t([^\t]+\t){20}({orig_cc}[^\t]+)\t({resp_cc}[^\t]+)\t({sensorname}[^\s]+)\s*"""
  ]
  DupFields = [ "id_orig_h->src_ip", "id_orig_p->src_port", "id_resp_h->dest_ip", "id_resp_p->dest_port", "sensorname->src_interface", "orig_ip_bytes->bytes_out", "resp_ip_bytes->bytes_in" ]
}
```