import typing
import os
import re
import json

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy import flow
from mitmproxy import types

from furl import furl


class Util:
    def __init__(self):
        pass

    @command.command('util.follow_301')
    def follow_301(self, flows: typing.Sequence[flow.Flow]) -> None:
        for flow in flows:
            if not flow.response.status_code == 301:
                return

            try:
                flow.request.url = flow.response.headers.get_all("location")[0]
            except:
                ctx.log.error("Error following URL")
                return

            ctx.master.commands.call("replay.client", [flow])

    @command.command('util.search')
    def search(self, flows: typing.Sequence[flow.Flow], search: str) -> None:
        s = "COMP6443{(.*?)}"

        found = 0

        ctx.log.info("Searching items")

        for flow in flows:
            try:
                res = [x.group() for x in re.finditer(s, flow.response.text)]

                for r in res:
                    ctx.log.info("Search found: {}".format(r))

                    found += 1
            except:
                ctx.log.error("Error following URL")
                return

        ctx.log.info("Searching found {} items".format(found))

class Brute:
    def __init__(self):
        pass

    def _brute(self, flows: typing.Sequence[flow.Flow], part: str, param: str, word_list: typing.List[str]) -> None:
        for flow in flows:
            try:
                if part == 'url':
                    pass
                elif part == 'path':
                    pass
                elif part == 'cookie':
                    pass
                elif part == 'form':
                    pass
                elif part == 'json':
                    pass
                else:
                    ctx.log.error('Invalid part')
                    return

                for el in word_list:
                    nf = flow.copy()

                    if part == 'url':
                        url  = furl(flow.request.url)

                        if param in url.args:
                            del url.args[param]

                        url.add({ param: el })

                        nf.request.url = url.url

                    elif part == 'path':
                        url  = furl(flow.request.url)
                        url.path = param

                        nf.request.url = url.url

                    elif part == 'cookie':
                        nf.request.cookies.set_all(param, [el])

                    elif part == 'form':
                        nf.request.urlencoded_form.set_all(param, [el])
                    
                    elif part == 'json':
                        #nf.request._set_urlencoded_form('{ ok: 2 }')
                        jd = json.loads(nf.request.content)
                        jd[param] = el

                        ctx.log.info(json.dumps(jd))

                        nf.request.content = json.dumps(jd).encode('utf8')
                        nf.request.headers["content-type"] = "application/json"

                        ctx.log.info(json.dumps(jd))

                    if "view" in ctx.master.addons:
                        ctx.log.error("TEST")

                        ctx.master.commands.call("view.flows.add", [nf])

                    ctx.master.commands.call("replay.client", [nf])
            except:
                pass

    @command.command('brute.enum')
    def enum(self, flows: typing.Sequence[flow.Flow], part: str, param: str, range_nums: str) -> None:
        try:
            from_r = int(range_nums.split(':')[0])
            to_r = int(range_nums.split(':')[1]) + 1
        except:
            ctx.log.error("Range of numbers must be in the form x:y")
            return

        word_list = []

        for x in range(from_r, to_r):
            word_list.append(str(x))
            # for 0000-9999 word_list.append('{:04d}'.format(x))

        self._brute(flows, part, param, word_list)

    @command.command('brute.list')
    def b_list(self, flows: typing.Sequence[flow.Flow], part: str, param: str, path: types.Path) -> None:
        if not os.path.isfile(path):
            ctx.log.error('Invalid wordlist')
            return

        word_list = []

        with open(path, 'r') as f:
            for line in f.readlines():
                word_list.append(line.strip())

        self._brute(flows, part, param, word_list)


addons = [
    Util(),
    Brute()
]
