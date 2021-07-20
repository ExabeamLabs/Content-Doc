#### Parser Content
```Java
{
Name = bro-smb_mapping
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "share-access"
  TimeFormat = "epoch_sec"
  Conditions = [ "/smb_mapping.log", "\t445\t" ]
  Fields = [
     """exabeam_host=({host}[\w.\-]{1,2000})""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|({share_path}[^\t]{1,2000}))\t(?:-|({service}[^\t]{1,2000}))\t(?:-|({native_file_system}[^\t]{1,2000}))\t(?:-|({share_type}[^\t]{1,2000}?))\s{0,100}$""",
     """({protocol}smb)"""
  ]
}
```