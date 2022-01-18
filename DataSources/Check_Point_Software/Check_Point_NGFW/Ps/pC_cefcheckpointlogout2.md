#### Parser Content
```Java
{
Name = cef-checkpoint-logout-2
  DataType = "vpn-logout"
  Conditions = [ """CEF:""", """|Check Point|Identity Awareness|""", """act=Log Out""", """vpn""" ]

cef-checkpoint-firewall = {
  Vendor = Check Point Software
  Product = Check Point NGFW
  Lms = ArcSight
  IsHVF = true
  TimeFormat = "epoch"
  Fields = [
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\Wrt=({time}\d{1,100})""",
    """\Wact=(|({action}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wifname=(|({src_interface}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Woriginsicname=(|({user_ou}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wproduct=(|({product_name}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wservice_id=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wrule_name=(|({rule}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wconn_direction=(|({direction}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wapp=(|({protocol}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wcp_severity=(|({alert_severity}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\W(s|d)user=({user_lastname}[^\s]{1,2000})\s{1,100}({user_firstname}[^\s]{1,2000})\s{1,100}-\s{1,100}\(({department}[^)]{1,2000})\)\s{1,100}-\s{1,100}({company}[^\s]{1,2000})\s{1,100}\((({user_email}[^@\s]{1,2000}@[^)]{1,2000})|({user}[^\)]{1,2000}))""",
    """\W(s|d)user=((CheckPoint|({user_lastname}[^\s]{1,2000}))\s{1,100}(Firewall|({user_firstname}[^\s]{1,2000}))\s{1,100})\((({user_email}[^\s@]{1,2000}@[^\)]{1,2000})|checkpointfw|({user}[^\)]{1,2000}))""",
    """\Wshost=(|({src_host}[\w\-.]{1,2000}?)(@({domain}[^\s@]{1,2000}))?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wsntdom=(|({domain}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\Wos_name=(|({os}.+?))(\s{1,100}\w+=|\s{0,100}$)""",
    """\WdestinationTranslatedAddress=(0\.0\.0\.0|({dest_translated_ip}[a-fA-F\d.:]{1,2000}))""",
    """\WsourceTranslatedAddress=(0\.0\.0\.0|({src_translated_ip}[a-fA-F\d.:]{1,2000}))""",
    """\Worigin=({origin_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wsrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\Wdst=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """dvc=({host}[a-fA-F\d.:]{1,2000})""",
    """ahost=({host}[^\s]{1,2000})""",
    """\Wspt=({src_port}\d{1,100})""",
    """\Wdpt=({dest_port}\d{1,100})""",
    """\Wserver_inbound_bytes=({bytes_in}\d{1,100})""",
    """\Wserver_outbound_bytes=({bytes_out}\d{1,100})""",
    """\Win=({bytes_in}\d{1,100})""",
    """\Wout=({bytes_out}\d{1,100})""",
    """categoryOutcome=(\/)?({outcome}.+?)\s\w+="""
  
}
```