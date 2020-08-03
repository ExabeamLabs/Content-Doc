#### Parser Content
```Java
{
Name = bro-share-access-2
  Vendor = Bro
  Lms = Direct
  DataType = "file-operations"
  TimeFormat = "epoch_sec"
  Conditions = [ "\tSMB::FILE_OPEN\t", "\t445\t" ]
  Fields = [
     """exabeam_host=([^@=]+@\s*)?({host}\S+)""",
     """({time}\d{10})\.\d{6}\t({conn_id}[^\t]+)\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({src_port}\d+?)|[^\t]+))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]*:[A-Fa-f0-9%.:]+(th0)?))|[^\t]+))\t(?:-|(({dest_port}\d+?)|[^\t]+))\t(?:-|({file_id}[^\t]+))\t(?:-|({event_name}[^\t]+))\t(?:-|({share_path}[^\t]+))\t(?:-|({file_name}[^\t]+))\t(?:-|({bytes}[^\t]+))\t(?:-|({src_file_name}[^\t]+))\t(?:-|({times_modified}[^\t]+))\t(?:-|({time_accessed}[^\t]+))\t(?:-|({time_created}[^\t]+))\t(?:-|({time_changed}[^\t]+?))\s*$""",
     """SMB::({accesses}FILE_OPEN)""",
     """\d{10}\.\d{6}\t([^\t]+\t){8}({file_path}({file_parent}[^\t]*?(\\u005c|[\\\/])*)({file_name}[^\t\\\/]+?(\.({file_ext}[^\t\\\/\.]+))?))\t""",
     """({protocol}SMB)"""
    ]
}
```