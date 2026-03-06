' --- NEW: defaults + config bootstrapping (local overrides + optional remote pull) ---
defaultVideoUrl = "http://pmd205604tn.download.theplatform.com.edgesuite.net/Demo_Sub_Account_2/411/535/ED_HD__571970.m3u8"
defaultAdUrl    = "https://devtools.web.roku.com/samples/sample.xml"

cfg = LoadAppConfig()
videoUrl = defaultVideoUrl
adUrl = defaultAdUrl

if cfg <> invalid then
    if cfg.videoUrl <> invalid and cfg.videoUrl <> "" then videoUrl = cfg.videoUrl
    if cfg.adUrl    <> invalid and cfg.adUrl    <> "" then adUrl    = cfg.adUrl

    ' If a remote admin URL is provided, fetch it and persist to cache:/ then reload
    if cfg.remoteConfigUrl <> invalid and cfg.remoteConfigUrl <> "" then
        if FetchAndPersistRemoteConfig(cfg.remoteConfigUrl) then
            cfg2 = LoadAppConfig()
            if cfg2 <> invalid then
                if cfg2.videoUrl <> invalid and cfg2.videoUrl <> "" then videoUrl = cfg2.videoUrl
                if cfg2.adUrl    <> invalid and cfg2.adUrl    <> "" then adUrl    = cfg2.adUrl
            end if
        end if
    end if
end if
' --- end NEW section ---

screen = CreateObject("roSGScreen")
scene = screen.CreateScene("MainScene")

'Specify content to be played
' NOTE: videoUrl now comes from config/defaults above
' videoUrl = "http://pmd205604tn.download.theplatform.com.edgesuite.net/Demo_Sub_Account_2/411/535/ED_HD__571970.m3u8"

'Specify VAST template containing ads to be rendered
' NOTE: adUrl now comes from config/defaults above
' adUrl = "https://devtools.web.roku.com/samples/sample.xml"

'Initialize RAF
m.adIface = Roku_Ads()

'Enable and specify audience identifiers to be passed into impression measurement tags
m.adIface.enableAdMeasurements(true)
m.adIface.setContentGenre("Entertainment")
m.adIface.setContentId("CSASAdSample" )

'Set and get the ads to be rendered
m.adIface.SetAdURL(adUrl)
m.adPods = m.adIface.GetAds()

'Create and configure a ContentNode containing the metadata of the content to be played.
myContentNode = createObject("roSgNode", "ContentNode")
myContentNode.url = videoUrl
myContentNode.length = 600
myContentNode.streamFormat = "hls"

'Combine video and ads into a single playlist
csasStream = m.adIface.constructStitchedStream(myContentNode, m.adPods)

' --- NEW: helper functions to support config loading and remote updates ---
Function LoadAppConfig() as Object
    ' Priority order: USB/ext -> cache -> tmp -> packaged fallback
    paths = [
        "ext:/app_config.json",  ' optional, on devices with USB support
        "cache:/app_config.json",
        "tmp:/app_config.json",
        "pkg:/app_config.json"   ' optional packaged default
    ]

    for each p in paths
        j = ReadAsciiFile(p)
        if j <> invalid and Len(j) > 0 then
            o = ParseJson(j)
            if o <> invalid then return o
        end if
    end for
    return invalid
End Function

Function FetchAndPersistRemoteConfig(url as String) as Boolean
    ut = CreateObject("roUrlTransfer")
    ut.SetUrl(url)
    ut.EnableEncodings(true) ' allow gzip/deflate

    rsp = ut.GetToString()
    if rsp <> invalid and Len(rsp) > 0 then
        if ParseJson(rsp) <> invalid then
            ' Persist remote config for subsequent runs
            ok = WriteAsciiFile("cache:/app_config.json", rsp)
            return ok
        end if
    end if
    return false
End Function
{
  "videoUrl": "http://example.cdn.net/path/to/your/stream.m3u8",
  "adUrl": "https://your.ad.server/vast.xml",
  "remoteConfigUrl": "https://your-admin-tool.example.com/roku/app_config.json"
}