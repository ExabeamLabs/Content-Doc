#### Parser Content
```Java
{
Name = centos-network-connection-failed
  Vendor = Linux
  Product = Linux CentOs
  Lms = Syslog
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  DataType = "network-connection-failed"
  Conditions = [ """KAFKA_CONNECT_SYSLOG""", """[FWD REJ]""", """SRC=""" ]
  Fields =[
    """exabeam_time=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\d\d\s{1,100}\d\d:\d\d:\d\d\s{1,100}({host}[^\s]{1,2000})\s{1,100}kernel:""",
    """SRC=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """DST=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """\s{1,100}({app}\w+)\s{1,100}\[FWD REJ\]""",
    """({action}FWD REJ)""",
    """SPT=({src_port}\d{1,100})""",
    """DPT=({dest_port}\d{1,100})""",
    """PROTO=({protocol}[^\s]{1,2000})""",
    """MAC=({src_mac}[^\s]{1,2000})""",
    """IN=({src_interface}[^\s]{1,2000})""",
    """OUT=({dest_interface}[^\s]{1,2000})""",
    """RES=({outcome}[^\s]{1,2000})"""
 ]
}
```