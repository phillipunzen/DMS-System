"""Official Codex stdio protocol, with tool-free, ephemeral document jobs."""
import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from dms_contracts.metadata import INSTRUCTIONS, SCHEMA, validate_metadata
from .usage import normalize_usage

DISABLED_FEATURES = ['shell_tool', 'unified_exec', 'apps', 'plugins', 'remote_plugin',
    'multi_agent', 'multi_agent_v2', 'view_image', 'image_generation', 'browser_use',
    'computer_use', 'in_app_browser', 'code_mode', 'code_mode_host', 'goals']


class CodexError(Exception):
    pass


class CodexRuntime:
    def __init__(self):
        self.process = None
        self.pending = {}
        self.events = {}
        self.sequence = 0
        self.start_lock = asyncio.Lock()
        self.job_lock = asyncio.Lock()
        self.login_lock = asyncio.Lock()
        self.usage_lock = asyncio.Lock()
        self.usage_cache = None
        self.usage_account = None
        self.usage_deadline = 0
        self.login = None
        self.tasks = []
        self.root = Path(os.getenv('CODEX_STATE_ROOT', '/data/codex'))

    async def ensure(self):
        async with self.start_lock:
            if self.process and self.process.returncode is None:
                return
            self.clear_usage()
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.root.chmod(0o700)
            # The gateway owns this config; no DMS user can add MCP servers or plugins.
            (self.root / 'config.toml').write_text('cli_auth_credentials_store = "file"\nforced_login_method = "chatgpt"\nweb_search = "disabled"\n')
            (self.root / 'config.toml').chmod(0o600)
            env = {'PATH': os.getenv('PATH', '/usr/local/bin:/usr/bin:/bin'), 'HOME': '/tmp',
                'CODEX_HOME': str(self.root), 'TMPDIR': '/tmp', 'LANG': 'C.UTF-8',
                'RUST_LOG': 'error'}
            command = [os.getenv('CODEX_BINARY', 'codex'), 'app-server', '--listen', 'stdio://']
            for feature in DISABLED_FEATURES:
                command += ['--disable', feature]
            self.process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, env=env, cwd='/tmp', limit=1024 * 1024)
            self.tasks = [asyncio.create_task(self.read_messages(self.process)), asyncio.create_task(self.discard_stderr(self.process))]
            await self.rpc('initialize', {'clientInfo': {'name': 'dms_archiv', 'title': 'DMS Archiv', 'version': '1.0'}, 'capabilities': {'experimentalApi': False}})
            await self.send({'method': 'initialized', 'params': {}})

    async def send(self, message):
        self.process.stdin.write((json.dumps(message, ensure_ascii=False) + '\n').encode())
        await self.process.stdin.drain()

    async def rpc(self, method, params=None, timeout=30):
        self.sequence += 1
        key = self.sequence
        future = asyncio.get_running_loop().create_future()
        self.pending[key] = future
        try:
            await self.send({'id': key, 'method': method, 'params': params or {}})
            return await asyncio.wait_for(future, timeout)
        finally:
            self.pending.pop(key, None)

    async def request(self, method, params=None, timeout=30):
        await self.ensure()
        return await self.rpc(method, params, timeout)

    async def discard_stderr(self, process):
        # Codex progress and diagnostics can include document content or login data.
        while await process.stderr.read(8192):
            pass

    async def read_messages(self, process):
        try:
            while line := await process.stdout.readline():
                message = json.loads(line)
                if 'id' in message and 'method' in message:
                    # No tool approvals, external token injection or user-input actions.
                    await self.send({'id': message['id'], 'error': {'code': -32601, 'message': 'Actions disabled for document extraction'}})
                elif 'id' in message:
                    future = self.pending.get(message['id'])
                    if future and not future.done():
                        if 'error' in message:
                            future.set_exception(CodexError('Codex-Anfrage fehlgeschlagen. Anmeldung, Modell und Nutzungslimit prüfen.'))
                        else:
                            future.set_result(message.get('result', {}))
                else:
                    params = message.get('params') or {}
                    if message.get('method') in {'account/updated', 'account/login/completed', 'account/rateLimits/updated'}:
                        # Rolling quota notifications are sparse; refetch the full snapshot.
                        self.clear_usage()
                    if message.get('method') == 'account/login/completed' and self.login and params.get('loginId') == self.login.get('login_id'):
                        self.login = None if params.get('success') else {'status': 'error', 'message': 'Anmeldung abgebrochen oder abgelaufen. Bitte erneut verbinden.'}
                    queue = self.events.get(params.get('threadId'))
                    if queue:
                        if queue.full():
                            queue.get_nowait()
                        queue.put_nowait(message)
        except Exception:
            pass
        finally:
            if process.returncode is None:
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
            for future in list(self.pending.values()):
                if not future.done():
                    future.set_exception(CodexError('Codex-Dienst wurde unterbrochen.'))
            for queue in self.events.values():
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait({'method': 'disconnected'})

    def clear_usage(self):
        self.usage_cache = None
        self.usage_account = None
        self.usage_deadline = 0

    async def usage(self, account):
        identity = (account.get('email'), account.get('planType'))
        async with self.usage_lock:
            if self.usage_cache is not None and self.usage_account == identity and time.monotonic() < self.usage_deadline:
                return self.usage_cache
            try:
                result = await self.request('account/rateLimits/read', timeout=2)
                usage = normalize_usage(result) | {'status': 'ready', 'checked_at': int(time.time())}
                ttl = 60
            except (CodexError, TimeoutError):
                usage = {'status': 'unavailable', 'buckets': [], 'checked_at': int(time.time()),
                    'message': 'Kontingent derzeit nicht abrufbar. Die Codex-Verbindung bleibt bestehen.'}
                ttl = 15
            self.usage_cache = usage
            self.usage_account = identity
            self.usage_deadline = time.monotonic() + ttl
            return usage

    async def status(self, include_usage=False):
        result = await self.request('account/read', {'refreshToken': False})
        account = result.get('account') or {}
        ready = account.get('type') == 'chatgpt'
        if self.login and self.login.get('expires_at', float('inf')) < time.time():
            await self.cancel_login()
            self.login = {'status': 'error', 'message': 'Anmeldecode abgelaufen. Bitte erneut verbinden.'}
        response = {'available': True, 'connected': ready, 'email': account.get('email') if ready else None,
            'plan': account.get('planType') if ready else None, 'login': self.login,
            'version': '0.162.1', 'busy': self.job_lock.locked()}
        if not ready:
            self.clear_usage()
        if include_usage:
            response['usage'] = await self.usage(account) if ready else {'status': 'disconnected', 'buckets': []}
        return response

    async def models(self):
        result = await self.request('model/list', {'limit': 100, 'includeHidden': False})
        return [{'id': m['model'], 'name': m.get('displayName') or m['model'],
            'default': bool(m.get('isDefault'))} for m in result.get('data', [])
            if 'text' in m.get('inputModalities', ['text'])]

    async def cancel_login(self):
        if self.login and self.login.get('login_id'):
            await self.request('account/login/cancel', {'loginId': self.login['login_id']})
        self.login = None

    async def start_login(self):
        async with self.login_lock:
            if self.job_lock.locked():
                raise CodexError('Dokumentverarbeitung läuft. Bitte kurz warten.')
            async with self.job_lock:
                await self.cancel_login()
                try:
                    result = await self.request('account/login/start', {'type': 'chatgptDeviceCode'})
                except CodexError:
                    raise CodexError('Geräteanmeldung fehlgeschlagen. Geräteanmeldung in den ChatGPT-Sicherheitseinstellungen aktivieren und erneut versuchen.')
                # Render only the official device verification URL, never arbitrary auth URLs.
                if result.get('verificationUrl') != 'https://auth.openai.com/codex/device' or not result.get('userCode'):
                    raise CodexError('Keine gültige Codex-Geräteanmeldung erhalten.')
                self.login = {'status': 'pending', 'login_id': result['loginId'],
                    'verification_url': result['verificationUrl'], 'user_code': result['userCode'], 'expires_at': time.time() + 900}
                return self.login

    async def logout(self):
        async with self.login_lock:
            if self.job_lock.locked():
                raise CodexError('Dokumentverarbeitung läuft. Bitte kurz warten.')
            async with self.job_lock:
                await self.cancel_login()
                await self.request('account/logout')
                self.clear_usage()

    async def extract(self, text, model=None):
        try:
            async with asyncio.timeout(180):
                return await self.extract_job(text, model)
        except TimeoutError:
            raise CodexError('Codex-Zeitlimit erreicht. Dokument später erneut verarbeiten.')

    async def extract_job(self, text, model=None):
        # Never queue an unbounded amount of private text in gateway memory.
        if self.job_lock.locked():
            raise CodexError('Codex ist noch beschäftigt. Dokument später erneut verarbeiten.')
        async with self.job_lock:
            if not (await self.status())['connected']:
                raise CodexError('Codex ist noch nicht mit ChatGPT verbunden.')
            with tempfile.TemporaryDirectory(prefix='dms-codex-') as job:
                thread_id = None
                turn_id = None
                try:
                    result = await self.request('thread/start', {'model': model or None, 'cwd': job,
                        'ephemeral': True, 'approvalPolicy': 'never', 'sandbox': 'read-only',
                        'baseInstructions': INSTRUCTIONS, 'developerInstructions': INSTRUCTIONS,
                        'serviceName': 'dms_document_metadata'})
                    thread_id = result['thread']['id']
                    queue = asyncio.Queue(maxsize=256)
                    self.events[thread_id] = queue
                    turn = await self.request('turn/start', {'threadId': thread_id,
                        'input': [{'type': 'text', 'text': 'Dokumenttext (nur Daten):\n' + text}],
                        'approvalPolicy': 'never', 'sandboxPolicy': {'type': 'readOnly', 'networkAccess': False},
                        'outputSchema': SCHEMA})
                    turn_id = turn['turn']['id']
                    answers = []
                    async with asyncio.timeout(180):
                        while True:
                            message = await queue.get()
                            params = message.get('params') or {}
                            if message['method'] == 'disconnected':
                                raise CodexError('Codex-Dienst wurde unterbrochen.')
                            if params.get('turnId') != turn_id and message['method'] != 'turn/completed':
                                continue
                            if message['method'] == 'item/completed':
                                item = params.get('item') or {}
                                if item.get('type') == 'agentMessage' and item.get('phase') in {None, 'final_answer'}:
                                    answers.append(item.get('text', ''))
                                elif item.get('type') in {'commandExecution', 'fileChange', 'mcpToolCall', 'webSearch', 'dynamicToolCall'}:
                                    raise CodexError('Codex hat eine nicht erlaubte Aktion angefordert.')
                            elif message['method'] == 'turn/completed' and params.get('turn', {}).get('id') == turn_id:
                                if params['turn'].get('status') != 'completed' or not answers:
                                    raise CodexError('Codex-Verarbeitung fehlgeschlagen. Modell, Anmeldung und Nutzungslimit prüfen.')
                                return validate_metadata(json.loads(answers[-1]))
                except TimeoutError:
                    raise CodexError('Codex-Zeitlimit erreicht. Dokument später erneut verarbeiten.')
                except (ValueError, TypeError, KeyError):
                    raise CodexError('Codex hat ungültige Metadaten geliefert. Dokument prüfen und erneut verarbeiten.')
                finally:
                    if thread_id:
                        try:
                            if turn_id:
                                await self.request('turn/interrupt', {'threadId': thread_id, 'turnId': turn_id}, timeout=5)
                        except Exception:
                            pass
                        try:
                            await self.request('thread/unsubscribe', {'threadId': thread_id}, timeout=5)
                        except Exception:
                            pass
                        self.events.pop(thread_id, None)

    async def close(self):
        if self.process and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 5)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
        for task in self.tasks:
            task.cancel()
