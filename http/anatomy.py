from mitmproxy import ctx,http
import mitmproxy

def purify(strs):
    return strs.replace("\n","").replace("\r","").strip()


class Counter:
    def __init__(self):
        self.num = 0
        options = open("options.txt","r+")
        self.a = purify(options.readline())
        print("settings read:"+self.a)
        options.close()
    def http_connect(self,flow: mitmproxy.http.HTTPFlow):
        # LAYER 1 : BLACKLIST BLOCK ------------------------
        fo = open("blacklist.txt","r+")
        line = fo.readline()
        while line:
            ctx.log.info("now comparing:"+line.replace("\n","").replace("\r",""))
            if flow.request.host == line.replace("\n","").replace("\r","").strip() and line.strip()!="" :
                flow.response = http.HTTPResponse.make(404)
                ctx.log.info(line+" BAN.")
                return
            line = fo.readline()
        fo.close()
        # LAYER 2 : AUTONOMOUS BLOCK -----------------------
        if self.a == "0": # all block
            flow.response = http.HTTPResponse.make(404)
            #flow.request.host = "www.bing.cn"
            ctx.log.info("ALL BLOCK CHAIN PERFORMED.")
        if self.a == "1" or self.a=="2": # only block black
        #    fo = open("blacklist.txt","r+")
        #    line = purify(fo.readline())
        #    while line:
        #        ctx.log.info("now matching:"+line)
        #        if flow.request.host == line:
        #            ctx.log.info("matched.block")
        #            flow.response = http.HTTPResponse.make(404)
        #        line = purify(fo.readline())
        #    fo.close()
            pass
        if self.a == "2": # smart block + black
            pass
        if self.a == "3": # only white
            fo = open("whitelist.txt","r+")
            line = purify(fo.readline())
            while line:
                ctx.log.info("now granting:"+line)
                if flow.request.host == line:
                    ctx.log.info("ACCESS GRANTED.")
                    return
                line = purify(fo.readline())
            flow.response = http.HTTPResponse.make(404)
            ctx.log.info("ACCORDING TO POLICY 3 , NOW DENIED.")    
            fo.close()
        ctx.log.info("ORZ -------------------------------")
    def request(self, flow):
        self.num = self.num + 1
        ctx.log.info("We've seen %d flows" % self.num)


addons = [
    Counter()
]
