#### Parser Content
```Java
{
Name = cef-carbonblack-network-connection
  Vendor = VMware
  Product = VMware Carbon Black Cloud Endpoint Standard
  Lms = ArcSight
  DataType = "network-connection"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """threatIndicators":""", """connection to""" , """sourceAddress="""]
  Fields = [
    """exabeam_host=([^=]+@\s{0,100})?({host}[\w\-.]+)""",
    """eventTime=({time}\d{1,100})""",
    """"deviceIpAddress=({src_ip}[A-Fa-f:\d.]+)""",
    """src=({src_ip}[A-Fa-f:\d.]+)""",
    """dst=({dest_ip}[^\s]+)""",
    """ext_netFlow_destPort=({dest_port}\d{1,100})""",
    """ext_netFlow_sourcePort=({src_port}\d{1,100})""",
    """deviceName=(({domain}[^\\\s"]+)\\+)?({src_host}[^\\\s"]+)""",
    """email=(({domain}[^\\\s"]+)\\+)?({user}\w+)""",
    """eventType=({alert_name}.+?)\s\w+=""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]+)""",
    """applicationPath=({process}(({directory}[^"=,]+)\\)?({process_name}[^\s\\]+))\s\w+=""",
    """applicationName=({process_name}.+?)\s\w+=""",
    """targetPriorityType=({alert_severity}.+?)\s\w+=""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory" ]
}
```