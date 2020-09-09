#### Parser Content
```Java
{
Name = s-xendesktop-remote-logon
  Vendor = Citrix XenDesktop
  Lms = Splunk
  DataType = "remote-logon"
  TimeFormat = "MM/dd/yyyy HH:mm:ss z"
  Conditions = [ """ DNSName="""", """ HostedMachineName="""", """ MachineSummaryState=""""]
  Fields = [
    """\sStartTime="({time}[^"]+?)"""",
    """\sDNSName="({dest_host}[^"]+?)"""",
    """\sIPAddress="({dest_ip}[^"]+?)"""",
    """\sLaunchedViaHostName="({src_host}[^"]+?)"""",
    """\sLaunchedViaIP="({src_ip}[^"]+?)"""",
    """\sClientName="({src_host}(?!HTML-)[^"]+?)"""",
    """\sClientAddress="({src_ip}(?!127\.0\.0\.1|0\.0\.0\.0|::0)[^"]+?)"""",
    """\sProtocol="({logon_type_text}[^"]+?)"""",
    """\sCatalogName="({catalog}[^"]+?)"""",
    """\sUserName="(({domain}[^"]+)\\)?({user}[^"]+?)"""",
    """\sUserSID="({user_sid}[^"]+?)"""",
  ]
  DupFields = ["dest_ip->host", "dest_host->host"]
}
```