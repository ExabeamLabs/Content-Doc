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
     """exabeam_host=({host}[\w.\-]+)""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|({share_path}[^\t]+))\t(?:-|({service}[^\t]+))\t(?:-|({native_file_system}[^\t]+))\t(?:-|({share_type}[^\t]+?))\s*$""",
     """({protocol}smb)"""
  ]
}
```