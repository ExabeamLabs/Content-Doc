#### Parser Content
```Java
{
Name = bro-dns
  Vendor = Bro
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "epoch_sec"
  Conditions = [ "/dns.log" ]
  Fields = [
     """({time}\d{10})\.\d{6}\t({uid}[^\t]+)\t(({id_orig_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+)\t(({id_orig_p}\d+?)|[^\t]+)\t(({id_resp_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+)\t(({id_resp_p}\d+?)|[^\t]+)\t({proto}[^\t]+)\t({trans_id}[^\t]+)\t({rtt}[^\t]+)\t({query}[^\t]+)\t({qclass}[^\t]+)\t({qclass_name}[^\t]+)\t({qtype}[^\t]+)\t({qtype_name}[^\t]+)\t({rcode}[^\t]+)\t({rcode_name}[^\t]+)\t({AA}[^\t]+)\t({TC}[^\t]+)\t({RD}[^\t]+)\t({RA}[^\t]+)\t({Z}[^\t]+)\t({answers}[^\t]+)\t({TTLs}[^\t]+)\t({rejected}[^\t]+?)\s*$""",
    """\d{10}\.\d{6}\t([^\t]+\t){14}(?:-|({dns_response_code}[^\t]+))\t"""
    ]
  DupFields = [ "id_orig_h->src_ip", "id_orig_p->src_port", "id_resp_h->dest_ip", "id_resp_p->dest_port", "proto->protocol", "qtype->query_type", "rejected->outcome" ]
}
```