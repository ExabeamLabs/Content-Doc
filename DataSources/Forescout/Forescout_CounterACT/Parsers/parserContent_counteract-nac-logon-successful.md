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
    """dvchost=({host}[^\s]+)\s\w+=""",
    """dvc=({host_ip}[a-fA-F\d:\.]+)""",
    """dhost=({dest_host}[^\s]+)""",
    """dst=({dest_ip}[a-fA-F\d:\.]+)""",
    """duser=(administrator|User|defaultuser1|({user}[^\s<]+))(<space>\(local\))?\s\w+=""",
    """dntdom=({domain}[^=]+?)\s\w+=""",
    """dmac=({dest_mac}[^\s]+)\s\w+=""",
    """cs2=({event_name}[^=]+?)\s\w+="""
  ]
}
```