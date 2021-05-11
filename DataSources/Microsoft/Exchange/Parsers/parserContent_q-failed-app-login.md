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
    """exabeam_host=([^=]+@\s{0,100})?({host}\S+)""",
    """SourceIp=({host}\S+)""",
    """s-ip=({dest_ip}[a-fA-F:\d.]+)""",
    """c-ip=({src_ip}[a-fA-F:\d.]+)""",
    """cs-username=(({domain}[^\\]+)\\+)?({user}[^\\\s]+)""",
    """cs\(User-Agent\)=({user_agent}.+?)\s{0,100}([\w\-\(\)]+=|$)""",
    """sc-bytes=({bytes_out}\d{1,100})""",
    """cs-bytes=({bytes_in}\d{1,100})""",
    """sc-status=({failure_reason}.+?)\s{0,100}([\w\-\(\)]+=|$)""",
    """s-port=({protocol}.+?)\s{0,100}([\w\-\(\)]+=|$)""",
  ]
}
```