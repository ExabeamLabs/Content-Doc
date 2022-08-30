#### Parser Content
```Java
{
Name = s-infoblox-one-dhcp-file-write
  DataType = "file-write"
  Vendor = Infoblox
  Product = BloxOne
  Lms = Splunk
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """manage_scheduled_backups[""", """: Backup to LOCAL was successful""" ]
  Fields = [
    """\d\d:\d\d:\d\d\s{1,100}({host}[\w.-]{1,2000})\s{1,100}({src_ip}[a-fA-F\d.:]{1,2000}?)\s{1,100}({additional_info}[^~]{1,2000}?)\s{0,100}$""",
    """Backup file ({file_path}({file_parent}[^"]{1,2000}\/)?({file_name}([^\/.]{1,2000})(\.({file_ext}[^"\s]{1,2000}))?))"""	  
   ]
  DupFields = [ "host->dest_host" ] 


}
```