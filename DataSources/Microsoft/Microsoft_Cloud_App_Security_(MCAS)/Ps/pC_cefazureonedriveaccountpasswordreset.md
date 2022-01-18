#### Parser Content
```Java
{
Name = cef-azure-onedrive-account-password-reset
  DataType = "account-password-reset"
  Conditions = [ """CEF:""", """|MCAS|SIEM_Agent|""", """|Reset password|""" ]

cef-azure-onedrive-account-password = {
  Vendor = Microsoft
  Product = Microsoft Cloud App Security (MCAS)
  Lms = ArcSight
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\|SIEM_Agent\|[^\|]{0,2000}\|[^\|]{0,2000}\|({activity}[^\|]{1,2000})\|""",
    """\|SIEM_Agent\|[^\|]{0,2000}\|({event_name}[^\|]{1,2000})\|""",
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\WdestinationServiceName =({app}.+?)\s{1,100}(\w+=|$)""",
    """\Wsuser=({user}[^@\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wsuser=({user_email}[^@\s]{1,2000}@[^@\s]{1,2000})\s{1,100}(\w+=|$)""",
    """\Wc6a1=\s{0,100}({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wmsg=({additional_info}.*?)\s{1,100}(\w+=|$)""",
  
}
```