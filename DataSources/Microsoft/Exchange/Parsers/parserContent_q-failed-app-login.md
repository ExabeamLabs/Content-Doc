#### Parser Content
```Java
{
Name = q-failed-app-login
  Vendor = Microsoft
  Product = Exchange
  Lms = QRadar
  DataType = "failed-app-login"
  TimeFormat = "yyyy-MM-dd'\ttime='HH:mm:ss"
  Conditions = [ "AgentDevice=MSIIS", "sc-status=401" ]
  Fields = [
    """date=({time}\d\d\d\d\-\d\d\-\d\d\s{0,100}time\=\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """SourceIp=({host}\S+)""",
    """s-ip=({dest_ip}[a-fA-F:\d.]{1,2000})""",
    """c-ip=({src_ip}[a-fA-F:\d.]{1,2000})""",
    """cs-username=(({domain}[^\\]{1,2000})\\+)?({user}[^\\\s]{1,2000})""",
    """cs\(User-Agent\)=({user_agent}.+?)\s{0,100}([\w\-\(\)]{1,2000}=|$)""",
    """sc-bytes=({bytes_out}\d{1,100})""",
    """cs-bytes=({bytes_in}\d{1,100})""",
    """sc-status=({failure_reason}.+?)\s{0,100}([\w\-\(\)]{1,2000}=|$)""",
    """s-port=({protocol}.+?)\s{0,100}([\w\-\(\)]{1,2000}=|$)""",
  ]
}
```