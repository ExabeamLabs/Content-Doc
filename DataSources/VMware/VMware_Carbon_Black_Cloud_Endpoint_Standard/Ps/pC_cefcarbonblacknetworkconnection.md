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
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}[\w\-.]{1,2000})""",
    """eventTime=({time}\d{1,100})""",
    """"deviceIpAddress=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """src=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """dst=({dest_ip}[^\s]{1,2000})""",
    """ext_netFlow_destPort=({dest_port}\d{1,100})""",
    """ext_netFlow_sourcePort=({src_port}\d{1,100})""",
    """deviceName =(({domain}[^\\\s"]{1,2000})\\+)?({src_host}[^\\\s"]{1,2000})""",
    """email=(({domain}[^\\\s"]{1,2000})\\+)?({user}\w+)""",
    """eventType=({alert_name}.+?)\s\w+=""",
    """threatIndicators[^":].+?=({alert_type}[^\s"]{1,2000})""",
    """applicationPath=({process}(({directory}[^"=,]{1,2000})\\)?({process_name}[^\s\\]{1,2000}))\s\w+=""",
    """applicationName =({process_name}.+?)\s\w+=""",
    """targetPriorityType=({alert_severity}.+?)\s\w+=""",
    """\Wmsg=({additional_info}.+?)\s{1,100}(\w+=|$)""",
  ]
  DupFields = [ "directory->process_directory" ]


}
```