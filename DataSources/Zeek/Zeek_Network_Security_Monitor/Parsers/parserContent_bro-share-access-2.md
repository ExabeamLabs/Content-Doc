#### Parser Content
```Java
{
Name = bro-share-access-2
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "epoch_sec"
  Conditions = [ "\tSMB::FILE_OPEN\t", "\t445\t" ]
  Fields = [
     """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({src_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_port}\d{1,100}?)|[^\t]{1,2000}))\t(?:-|({file_id}[^\t]{1,2000}))\t(?:-|({event_name}[^\t]{1,2000}))\t(?:-|({share_path}[^\t]{1,2000}))\t(?:-|({file_name}[^\t]{1,2000}))\t(?:-|({bytes}[^\t]{1,2000}))\t(?:-|({src_file_name}[^\t]{1,2000}))\t(?:-|({times_modified}[^\t]{1,2000}))\t(?:-|({time_accessed}[^\t]{1,2000}))\t(?:-|({time_created}[^\t]{1,2000}))\t(?:-|({time_changed}[^\t]{1,2000}?))\s{0,100}$""",
     """SMB::({accesses}FILE_OPEN)""",
     """\d{10}\.\d{6}\t([^\t]{1,2000}\t){8}({file_path}({file_parent}[^\t]{0,2000}?(\\u005c|[\\\/])*)({file_name}[^\t\\\/]{1,2000}?(\.({file_ext}[^\t\\\/\.]{1,2000}))?))\t""",
     """({protocol}SMB)"""
    ]
}
```