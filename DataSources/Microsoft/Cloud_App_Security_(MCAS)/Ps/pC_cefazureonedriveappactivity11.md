#### Parser Content
```Java
{
Name = cef-azure-onedrive-app-activity-11
  Conditions = [ """CEF:""", """|MCAS|SIEM_Agent|""", """|Create item|""" ]

cef-azure-onedrive-app-activity = {
  Vendor = Microsoft
  Product = Cloud App Security (MCAS)
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\|SIEM_Agent\|[^\|]{0,2000}\|[^\|]{0,2000}\|({activity}[^\|]{1,2000})\|""",
    """\|SIEM_Agent\|[^\|]{0,2000}\|({accesses}[^\|]{1,2000})\|""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WdestinationServiceName =({app}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}[^@\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@({email_domain}[^@\s]{1,2000}))\s{1,100}(\w+=|$)""",
    """\Wc6a1=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wmsg=({additional_info}.*?)\s{1,100}(\w+=|$)""",
    """\Wmsg=.*?\s{1,100}folder\s{1,100}(\([^\)]{0,2000}\):\s{0,100})?({object}.*?)\s{1,100}(\w+=|$)""",
    """\WrequestClientApplication=(|({user_agent}.*?))\s{1,100}(\w+=|$)""",
  
}
```