#### Parser Content
```Java
{
Name = bro-kerberos
  Vendor = Bro
  Lms = Direct
  DataType = "remote-access"
  TimeFormat = "epoch_sec"
  Conditions = ["/kerberos.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|({request_type}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({service_name}[^\/\t]+)).+?\t(?:-|({outcome}[^\t]+))\t(?:-|({result_code}[^\t]+))\t(?:-|({issue_time}[^\t]+))\t(?:-|({expiry_time}[^\t]+))\t(?:-|({ticket_encryption_type}[^\t]+))\t({ticket_options}[^\t]+\t[^\t]+)\t(?:-|({client_cert_subject}[^\t]+))\t(?:-|([^\t]+))\t(?:-|({server_cert_subject}[^\t]+))\t(?:-|([^\t]+?))\s*$"""
    """\d{10}\.\d{6}\t([^\t]+\t){6}({user}[^\/]+)\/({domain}[^\t]+)\t""",
    """\d{10}\.\d{6}\t([^\t]+\t){7}({dest_host}[^\/]+)\$"""
  ]
}
```