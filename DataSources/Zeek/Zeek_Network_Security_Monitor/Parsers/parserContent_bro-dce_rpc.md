#### Parser Content
```Java
{
Name = bro-dce_rpc
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "remote-access"
  TimeFormat = "epoch_sec"
  Conditions = [ "/dce_rpc.log" ]
  Fields = [
     """exabeam_host=([^@=]+@\s{0,100})?({host}\S+)""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d{1,100}?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({dest_host}[^\t]+))\t(?:-|({process_name}[^\t]+?))\s{0,100}$""",
    ]
}
```