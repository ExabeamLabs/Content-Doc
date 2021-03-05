#### Parser Content
```Java
{
Name = bro-dce_rpc
  Vendor = Bro
  Product = Bro
  Lms = Direct
  DataType = "remote-access"
  TimeFormat = "epoch_sec"
  Conditions = [ "/dce_rpc.log" ]
  Fields = [
     """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|([^\t]+))\t(?:-|([^\t]+))\t(?:-|({dest_host}[^\t]+))\t(?:-|({process_name}[^\t]+?))\s*$""",
    ]
}
```