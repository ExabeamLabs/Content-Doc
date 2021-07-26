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
     """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|({dest_host}[^\t]{1,2000}))\t(?:-|({process_name}[^\t]{1,2000}?))\s{0,100}$""",
    ]
}
```