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
    """exabeam_host=({host}[\w.\-]+)""",
    """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d{1,100}?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]+))\t(?:-|({user}[^\t]+))\t(?:-|({src_host}[^\t]+))\t(?:-|({domain}[^\t]+))\t(?:-|({outcome}[^\t]+))\t(?:-|({result_code}[^\t]+?))\s{0,100}$"""
  ]
}
```