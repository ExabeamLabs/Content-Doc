#### Parser Content
```Java
{
Name = s-xendesktop-remote-logon
  Vendor = Citrix
  Product = Citrix XenDesktop
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss z"
  Conditions = [ """ DNSName="""", """ HostedMachineName="""", """ MachineSummaryState=""""]
  Fields = [
    """\sStartTime="({time}[^"]{1,2000}?)"""",
    """\sDNSName="({dest_host}[^"]{1,2000}?)"""",
    """\sIPAddress="({dest_ip}[^"]{1,2000}?)"""",
    """\sLaunchedViaHostName="({src_host}[^"]{1,2000}?)"""",
    """\sLaunchedViaIP="({src_ip}[^"]{1,2000}?)"""",
    """\sClientName="({src_host}(?!HTML-)[^"]{1,2000}?)"""",
    """\sClientAddress="({src_ip}(?!127\.0\.0\.1|0\.0\.0\.0|::0)[^"]{1,2000}?)"""",
    """\sProtocol="({logon_type_text}[^"]{1,2000}?)"""",
    """\sCatalogName="({catalog}[^"]{1,2000}?)"""",
    """\sUserName="(({domain}[^"]{1,2000})\\)?({user}[^"]{1,2000}?)"""",
    """\sUserSID="({user_sid}[^"]{1,2000}?)"""",
  ]
  DupFields = ["dest_ip->host", "dest_host->host"]
}
```