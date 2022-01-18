#### Parser Content
```Java
{
Name = cef-azure-onedrive-file-activity-4
  Conditions = [ """CEF:""", """|MCAS|SIEM_Agent|""", """|Sync file upload|""" ]

cef-azure-onedrive-file-activity = {
  Vendor = Microsoft
  Product = Microsoft Cloud App Security (MCAS)
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\|SIEM_Agent\|[^\|]{0,2000}\|[^\|]{0,2000}\|({activity}[^\|]{1,2000})\|""",
    """\|SIEM_Agent\|[^\|]{0,2000}\|({accesses}[^\|]{1,2000})\|""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WdestinationServiceName =({app}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}[^@\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@[^@\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wc6a1=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wmsg=({additional_info}.*?)\s{1,100}(\w+=|$)""",
    """\Wmsg=(.+?):\s{0,100}({file_type}[^\s]{1,2000})\s{1,100}({file_path}({file_parent}[^=]{1,2000}?)[\\\/]{1,2000}(|({file_name}[^\\\/]{0,2000}?(\.({file_ext}[^\\\/:\s\.]{1,2000}))?)))(\s{0,100}(with|folder|to file|;)\s{1,100}.*?)?\s{1,100}(?:$|\w+=)""",

  
}
```