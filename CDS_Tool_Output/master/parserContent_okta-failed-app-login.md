#### Parser Content
```Java
{
Name = okta-failed-app-login
    Vendor = Okta
    Product = Okta MFA
    Lms = Direct
    DataType = "failed-app-login"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Conditions = [ """,Sign-""", """n Failed """]
    Fields = [
        """([^,]*,){2}({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)""",
        """Sign-(i|I)n Failed.*?([^,]*,){3}({src_ip}[^,]+)""",
        """exabeam_host=({host}[^\s]+)""",
        """Verification failed for user:\s*(({user_email}[^"@]+@[^"@]+)|({user}[^"]+))"*,""",
        """([^,]*,){4}(({user_email}[^,@]+@[^,@]+)|({user}[^,]+))""",
        """Sign-(i|I)n Failed\s*-\s*({failure_reason}[^:",]+)""",
        """([^,]*,){11}\/app\/({app}[^\/]+)""",
    ]
  }
]


include "./parsers_wazuh.conf"
include "./parsers_shared.conf"
include "./parsers_windows.conf"
include "./parsers_pmp.conf"
include "./parsers_digitalguardian.conf"
include "./parsers_exchange.conf"
include "./parsers_duo.conf"
include "./parsers_unix.conf"
include "./parsers_microsoft_azure.conf"
include "./parsers_box.conf"
include "./parsers_okta.conf"
include "./parsers_juniper.conf"
include "./parsers_carbonblack.conf"
include "./parsers_paloalto.conf"
include "./parsers_mcafee.conf"
include "./parsers_citrix.conf"
include "./parsers_symantec.conf"
include "./parsers_microsoft.conf"
include "./parsers_fireeye.conf"
include "./parsers_imperva.conf"
include "./parsers_sophos.conf"
include "./parsers_checkpoint.conf"
include "./parsers_iis.conf"
include "./parsers_cisco.conf"
include "./parsers_fortinet.conf"
include "./parsers_vmware.conf"
include "./parsers_bluecoat.conf"
include "./parsers_trendmicro.conf"
include "./parsers_github.conf"
include "./parsers_rdirectory.conf"
include "./parsers_f5vpn.conf"
include "./parsers_stealthbits.conf"
include "./parsers_bro.conf"
include "./parsers_cyberarkvault.conf"
include "./parsers_zscaler.conf"
include "./parsers_proofpoint.conf"
include "./parsers_rsa.conf"
include "./parsers_websense.conf"
include "./parsers_crowdstrike.conf"
include "./parsers_skyfence.conf"
include "./parsers_svn.conf"
include "./parsers_ibm.conf"
include "./parsers_bromium.conf"
include "./parsers_dropbox.conf"
include "./parsers_salesforce.conf"
include "./parsers_windows_chinese.conf"
include "./parsers_bitglass.conf"
include "./parsers_rangeraudit.conf"
include "./parsers_damballafailsafe.conf"
include "./parsers_windows_japanese.conf"
include "./parsers_dtex.conf"
include "./parsers_oracle.conf"
include "./parsers_ovirt.conf"
include "./parsers_adaudit.conf"
include "./parsers_observeit.conf"
include "./parsers_kiteworks.conf"
include "./parsers_infowatch.conf"
include "./parsers_lanscopecat.conf"

SentinelOneParserTemplates = {

  cef-sentinelone-security-alert = {
    Vendor = SentinelOne
    Lms = ArcSight
    DataType = "alert"
    TimeFormat = "yyyy-MM-dd'T'HH:mm:ss"
    Fields = [
      """CEF:([^\|]*\|){5}({alert_name}[^\|]+)\|({alert_severity}[^\|]+)\|""",
      """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d)\.\d+Z\s+({host}\S+)""",
      """\seventType:(|({alert_type}.+?))(\s+\w+:|\s*$)""",
      """\sagentId:(|({agent_id}.+?))(\s+\w+:|\s*$)""",
      """\sagentIp:({dest_ip}[a-fA-F\d.:]+)""",
      """\sagentName:(|({dest_host}.+?))(\s+\w+:|\s*$)""",
      """\sagentfileFullNameGroupId:(|({file_path}({file_parent}.*?[\\\/]+)?({file_name}[^\\\/]+?(\.({file_ext}\w+))?)))(\s+\w+:|\s*$)""",
      """\sprocessName:(|({process_name}.+?))(\s+\w+:|\s*$)""",
      """\sid:(|({alert_id}.+?))(\s+\w+:|\s*$)""",
    ]
  }
}

AirlockTemplates = {
  AirlockEvent = {
    Vendor = Airlock
    Product = Airlock
    Lms = Splunk
    TimeFormat = "M/d/yy h:mm:ss a"
    Fields = [
      """\sstart_time="({time}\d+\/\d+\/\d+ \d+:\d+:\d+ \w+)""",
      """\sseverity="({alert_severity}[^"]+)"""",
      """\ssystem_name="({host}[^"]+)"""",
      """\ssession_id="({session_id}[^"]+)"""",
      """\sremote_port="({src_port}[^"]+)"""",
      """\sremote_ip="({src_ip}[^"]+)"""",
      """\sremarks="({activity}[^"]+)"""",
      """\slocal_port="({dest_port}[^"]+)"""",
      """\slocal_ip="({dest_ip}[^"]+)"""",
      """\sevent_type="({event_name}[^"]+)"""",
      """\sevent_id="({event_id}[^"]+)"""",
      """\scommand="({action}[^"]+)"""",
      """\suser_name="(unknown|({user}[^"]+))"""",
      """\sdomain="(Default|({domain}[^"]+))"""",
      """\sfile_size="({bytes}[^"]+)"""",
      """\sfile_path="(\w+:_)?({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+?(\.({file_ext}[^\\\/\.;"]+))))"""
      """\sfile_path="(\w+:_)?({file_path}({file_parent}(?:[^";]+)?[\\\/;])?({file_name}[^\\\/";]+(\.({file_ext}[^\\\/\.;"]+))))""" 
    ]
    DupFields = ["host->dest_host"]
  }
}
ProWatchParserTemplates = {

prowatch-badge-access = {
  Vendor = ProWatch
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Fields = [
    """exabeam_host=({host}[\w.\-]+)""",
    """:f+:({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\{""",
    """"((?i)location)":\s*"\s*({location_building}[^"]+?)\s*"""",
    """"((?i)descrp)":\s*"\s*({location_door}[^"]+?)\s*"""",
    """"evnt_dat":\s*"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d+Z)""",
    """"EVNT_DAT":\s*"({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """"BADGENO":\s*"({badge_id}[^"]+)""",
    """"((?i)cardno)":\s*"({badge_id}\d+)""",
    """"((?i)comp_name)":\s*"\s*({additional_info}[^"]+?)\s*"""",
    """"((?i)evnt_descrp)":\s*"\s*({outcome}[^"]+?)\s*"""",
    """"((?i)threat_lev)":({threat_level}\d+)""",
    """"((?i)fname)":"\s*({first_name}[^"]+?)\s*"""",
    """"((?i)lname)":"\s*({last_name}[^"]+?)\s*"""",
    """"((?i)badge_employeeid)":"\s*({employee_id}[^"]+?)\s*"""",
    """"((?i)cardstatus_descrp)":"\s*({card_status}[^"]+?)\s*""""
  ]
}

s-prowatch-badge-access = {
    Vendor = ProWatch
    Lms = Splunk
    DataType = "physical-access"
    TimeFormat =  "yyyy-MM-dd HH:mm:ss"
    Fields = [
      """EVNT_DAT="({time}\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d).""",
      """CARDNO="({badge_id}[^"]+)"""",
      """LOCATION="({location_door}[^"]+)"""",
      """FNAME="({first_name}[^"]+)"""",
      """LNAME="({last_name}[^"]+?)\s*"""",
      """LOOP_DESCRP="({location_building}[^"]+)"""",
      """EVNT_DESCRP="({outcome}[^"]+)"""",
      """exabeam_host=([^=]*@\s*)?({host}[^\s]+)"""
    ]
  }
```