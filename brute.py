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


class Brute:
    def __init__(self):
        pass

    def check_url_param(self, url, param):
        params = list(url.args.keys())

        if not param:
            return False

        if param not in params:
            return False

        return True

    @command.command('brute.test')
    def test(self, flows: typing.Sequence[flow.Flow]) -> None:
        for flow in flows:
            try:
                flow.request.urlencoded_form = flow.request.urlencoded_form.set_all('user_login', ['a@what.com'])
                ctx.log.info(flow.request.urlencoded_form)
            except:
                pass

    # Util commands
    @command.command('brute.follow_301')
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

    @command.command('brute.search')
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

    # target: url, cookie, param: q, range_nums: 1:100
    @command.command('brute.enum')
    def enum(self, flows: typing.Sequence[flow.Flow], target: str, param: str, range_nums: str) -> None:
        for flow in flows:
            try:
                if target == 'url':
                    '''if not self.check_url_param(url, param):
                        ctx.log.error('Invalid param')
                        return'''
                    pass
                elif target == 'cookie':
                    pass
                elif target == 'form':
                    pass
                else:
                    ctx.log.error('Invalid target')
                    return

                try:
                    from_r = int(range_nums.split(':')[0])
                    to_r = int(range_nums.split(':')[1]) + 1
                except:
                    ctx.log.error("Range of numbers must be in the form x:y")
                    return

                for i in range(from_r, to_r):
                    nf = flow.copy()

                    if target == 'url':
                        url  = furl(flow.request.url)

                        if param in url.args:
                            del url.args[param]

                        url.add({ param: i })

                        nf.request.url = url.url

                    elif target == 'cookie':
                        nf.request.cookies.set_all(param, [str(i)])

                    elif target == 'form':
                        nf.request.urlencoded_form.set_all(param, [str(i)])

                    if "view" in ctx.master.addons:
                        ctx.log.error("TEST")

                        ctx.master.commands.call("view.flows.add", [nf])

                    ctx.master.commands.call("replay.client", [nf])
            except:
                pass

    @command.command('brute.list')
    def b_list(self, flows: typing.Sequence[flow.Flow], target: str, param: str, path: types.Path) -> None:
        for flow in flows:
            try:
                url  = furl(flow.request.url)

                if target == 'url':
                    '''if not self.check_url_param(url, param):
                        ctx.log.error('Invalid param')
                        return'''
                    pass
                elif target == 'cookie':
                    pass
                elif target == 'form':
                    pass
                elif target == 'json':
                    pass
                else:
                    ctx.log.error('Invalid target')
                    return

                if not os.path.isfile(path):
                    ctx.log.error('Invalid wordlist')
                    return

                with open(path, 'r') as f:
                    for line in f.readlines():
                        line = line.strip()

                        nf = flow.copy()

                        if target == 'url':
                            url  = furl(flow.request.url)

                            if param in url.args:
                                del url.args[param]

                            url.add({ param: line })

                            nf.request.url = url.url

                        elif target == 'cookie':
                            nf.request.cookies.set_all(param, [line])

                        elif target == 'form':
                            nf.request.urlencoded_form.set_all(param, [line])
                        
                        elif target == 'json':
                            #nf.request._set_urlencoded_form('{ ok: 2 }')
                            jd = json.loads(nf.request.content)
                            jd[param] = line

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

addons = [
    Brute()
]
