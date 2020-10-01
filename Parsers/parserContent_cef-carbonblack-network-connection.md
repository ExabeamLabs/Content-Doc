#### Parser Content
```Java
{
Name = cef-carbonblack-network-connection
  Vendor = Carbon Black
  Product = CB Defense
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """threatIndicators":""", """connection to""" , """sourceAddress="""]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}[\w\-.]+)""",
    """eventTime=({time}\d+)""",
    """"deviceIpAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[^\s]+)""",
    """ext_netFlow_destPort=({dest_port}\d+)""",
    """ext_netFlow_sourcePort=({src_port}\d+)""",
    """deviceName=(({domain}[^\\\s"]+)\\+)?({src_host}[^\\\s"]+)""",
    """email=(({domain}[^\\\s"]+)\\+)?({user}\w+)""",
    """eventType=({alert_name}.+?)\s\w+=""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]+)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s\w+=""",
    """applicationName=({process_name}.+?)\s\w+=""",
    """targetPriorityType=({alert_severity}.+?)\s\w+=""",
    """\Wmsg=({additional_info}.+?)\s+(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```