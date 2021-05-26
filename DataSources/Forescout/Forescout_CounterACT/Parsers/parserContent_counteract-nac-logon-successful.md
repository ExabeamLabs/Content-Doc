#### Parser Content
```Java
{
Name = counteract-nac-logon-successful
  Vendor = Forescout
  Product = Forescout CounterACT
  Lms = Direct
  DataType = "nac-logon"
  TimeFormat= "epoch"
  Conditions = [ """CEF:""", """|ForeScout Technologies|CounterAct""", """|COMPLIANCE|host is compliant|""", """Interactive Logon Events""", """Logon Event """ ]
  Fields = [
    """rt=({time}\d{1,100})""",
    """dvchost=({host}[^\s]{1,2000})\s\w+=""",
    """dvc=({host_ip}[a-fA-F\d:\.]{1,2000})""",
    """dhost=({dest_host}[^\s]{1,2000})""",
    """dst=({dest_ip}[a-fA-F\d:\.]{1,2000})""",
    """duser=(administrator|User|defaultuser1|({user}[^\s<]{1,2000}))(<space>\(local\))?\s\w+=""",
    """dntdom=({domain}[^=]{1,2000}?)\s\w+=""",
    """dmac=({dest_mac}[^\s]{1,2000})\s\w+=""",
    """cs2=({event_name}[^=]{1,2000}?)\s\w+="""
  ]
}
```