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
    """date=({time}\d\d\d\d\-\d\d\-\d\d\s*time\=\d\d:\d\d:\d\d)""",
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """SourceIp=({host}\S+)""",
    """s-ip=({dest_ip}[a-fA-F:\d.]+)""",
    """c-ip=({src_ip}[a-fA-F:\d.]+)""",
    """cs-username=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)""",
    """cs\(User-Agent\)=({user_agent}.+?)\s*([\w\-\(\)]+=|$)""",
    """sc-bytes=({bytes_out}\d+)""",
    """cs-bytes=({bytes_in}\d+)""",
    """sc-status=({failure_reason}.+?)\s*([\w\-\(\)]+=|$)""",
    """s-port=({protocol}.+?)\s*([\w\-\(\)]+=|$)""",
  ]
}
```