#### Parser Content
```Java
{
Name = bro-kerberos
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "remote-access"
  TimeFormat = "epoch_sec"
  Conditions = ["/kerberos.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|({request_type}[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|({service_name}[^\/\t]{1,2000})).+?\t(?:-|({outcome}[^\t]{1,2000}))\t(?:-|({result_code}[^\t]{1,2000}))\t(?:-|({issue_time}[^\t]{1,2000}))\t(?:-|({expiry_time}[^\t]{1,2000}))\t(?:-|({ticket_encryption_type}[^\t]{1,2000}))\t({ticket_options}[^\t]{1,2000}\t[^\t]{1,2000})\t(?:-|({client_cert_subject}[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|({server_cert_subject}[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}?))\s{0,100}$"""
    """\d{10}\.\d{6}\t([^\t]{1,2000}\t){6}({user}[^\/]{1,2000})\/({domain}[^\t]{1,2000})\t""",
    """\d{10}\.\d{6}\t([^\t]{1,2000}\t){7}({dest_host}[^\/]{1,2000})\$"""
  ]
}
```