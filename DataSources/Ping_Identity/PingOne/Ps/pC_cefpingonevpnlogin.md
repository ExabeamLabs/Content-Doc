#### Parser Content
```Java
{
Name = cef-pingone-vpn-login
  DataType = "vpn-login"
  Conditions = [ """destinationServiceName =Ping""","""flexString2=Authentication""", """Requested Application Name: VPN""" , """request=Success"""]

cef-ping-events-2 = {
  Vendor = Ping Identity
  Product = PingOne
  Lms = Direct
  TimeFormat = "epoch"  
  Fields = [
    """exabeam_host=({host}[^\s]{1,2000})""",
    """end=({time}\d{1,100})""",
    """IP\sAddress:\s{0,100}({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """Requested\sApplication\sID:\s{0,100}(N\/A|({requested_app_id}.*?))(\\n)*\s{0,100}Requested\sApplication\sName""",
    """Requested\sApplication\sName:\s{0,100}({requested_app}.*?)(\\n)*\s{0,100}Password\sReset""",
    """request=({outcome}[^\s]{1,2000})""",
    """requestClientApplication=({app}.*?)\s\w+=""",
    """suid=({username}[^\s]{1,2000})""",
    """suser=({user}[^\s]{1,2000})""",
    """flexString2=({action}.*?)\sDetails""",
    """Country:\s({country}.*?)\s{0,100}(\\n)*New Device""",
    """Mobile OS Version:\s({os}.*?)\s{0,100}(\\n)*Device Model""",
    """Device Model:\s(N\/A|({device}.*?))\s{0,100}(\\n)*Device Lock""",
  
}
```