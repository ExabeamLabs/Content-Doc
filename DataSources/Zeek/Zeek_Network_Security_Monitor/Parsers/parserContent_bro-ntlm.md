#### Parser Content
```Java
{
Name = bro-ntlm
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "ntlm-logon"
  TimeFormat = "epoch_sec"
  Conditions = [ "/ntlm.log" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|({user}[^\t]{1,2000}))\t(?:-|({src_host}[^\t]{1,2000}))\t(?:-|({domain}[^\t]{1,2000}))\t(?:-|({outcome}[^\t]{1,2000}))\t(?:-|({result_code}[^\t]{1,2000}?))\s{0,100}$"""
  ]
}
```