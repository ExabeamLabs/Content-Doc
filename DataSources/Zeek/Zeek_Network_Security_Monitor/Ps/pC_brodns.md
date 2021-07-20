#### Parser Content
```Java
{
Name = bro-dns
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "dns-response"
  TimeFormat = "epoch_sec"
  Conditions = [ "/dns.log" ]
  Fields = [
     """({time}\d{10})\.\d{6}\t({uid}[^\t]{1,2000})\t(({id_orig_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000})\t(({id_orig_p}\d{1,100}?)|[^\t]{1,2000})\t(({id_resp_h}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000})\t(({id_resp_p}\d{1,100}?)|[^\t]{1,2000})\t({proto}[^\t]{1,2000})\t({trans_id}[^\t]{1,2000})\t({rtt}[^\t]{1,2000})\t({query}[^\t]{1,2000})\t({qclass}[^\t]{1,2000})\t({qclass_name}[^\t]{1,2000})\t({qtype}[^\t]{1,2000})\t({qtype_name}[^\t]{1,2000})\t({rcode}[^\t]{1,2000})\t({rcode_name}[^\t]{1,2000})\t({AA}[^\t]{1,2000})\t({TC}[^\t]{1,2000})\t({RD}[^\t]{1,2000})\t({RA}[^\t]{1,2000})\t({Z}[^\t]{1,2000})\t({answers}[^\t]{1,2000})\t({TTLs}[^\t]{1,2000})\t({rejected}[^\t]{1,2000}?)\s{0,100}$""",
    """\d{10}\.\d{6}\t([^\t]{1,2000}\t){14}(?:-|({dns_response_code}[^\t]{1,2000}))\t"""
    ]
  DupFields = [ "id_orig_h->src_ip", "id_orig_p->src_port", "id_resp_h->dest_ip", "id_resp_p->dest_port", "proto->protocol", "qtype->query_type", "rejected->outcome" ]
}
```