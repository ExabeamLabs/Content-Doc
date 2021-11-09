#### Parser Content
```Java
{
Name = q-adfs-auth-failed-1
  DataType = "authentication-failed"
  Conditions = [ """Message=The Federation Service failed to issue a valid token""", """EventIDCode=1201""" ]
}
q-adfs-auth = {
    Vendor = Microsoft
    Product = Windows
    Lms = QRadar
    TimeFormat = "epoch_sec"
    Fields = [
      """\sTimeGenerated=({time}\d{1,100})""",
      """\sEventIDCode=({event_code}\d{1,100})""",
      """\sComputer=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sUser=({account}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sDomain=({account_domain}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
      """\sMessage=({event_name}[^=\.]{1,2000})""",
      """<IpAddress>({additional_info}[^<]{1,2000})</IpAddress>""",
      """<IpAddress>({src_ip}[a-fA-F\d.:]{1,2000})</IpAddress>""",
      """({src_ip}[a-fA-F\d.:]{1,2000})</IpAddress>""",
      """<ClaimsProvider>(?:N\/A|({domain}[^<]{1,2000}))</ClaimsProvider>""",
      """<UserId>(({domain}[^<\\]{1,2000})\\+)?({user}(?!N\/A)[^<\\]{1,2000})</UserId>""",
      """<FailureType>(?:None|({failure_reason}[^<]{1,2000}))</FailureType>""",
      """<Server>({auth_server}[^<]{1,2000})</Server>""",
      """:({service}[^:>]{1,2000})</RelyingParty>""",
      """<PrimaryAuth>(N\/A|[^<]{1,2000}?\/({auth_method}[^<\/]{1,2000}))</PrimaryAuth>""",
    ]}
```