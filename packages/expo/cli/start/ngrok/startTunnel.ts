import * as path from 'path';
import slugify from 'slugify';

import { getActorDisplayName, getUserAsync } from '../../api/user/user';
import * as Log from '../../log';
import { delayAsync } from '../../utils/delay';
import { CommandError } from '../../utils/errors';
import { ProjectSettings } from '../api/ProjectSettings';
import UserSettings from '../api/UserSettings';
import { getNativeDevServerPort } from '../devServer';
import {
  startAdbReverseAsync,
  stopAdbReverseAsync,
} from '../platforms/android/AndroidDeviceBridge';
import * as NgrokServer from './ngrokServer';
import { NgrokOptions, resolveNgrokAsync } from './resolveNgrok';

const NGROK_CONFIG = {
  authToken: '5W1bR67GNbWcXqmxZzBG1_56GezNeaX6sSRvn8npeQ8',
  authTokenPublicId: '5W1bR67GNbWcXqmxZzBG1',
  domain: 'exp.direct',
};

const TUNNEL_TIMEOUT = 10 * 1000;

function getNgrokConfigPath() {
  return path.join(UserSettings.getDirectory(), 'ngrok.yml');
}

function randomIdentifier(length: number = 6): string {
  const alphabet = '23456789qwertyuipasdfghjkzxcvbnm';
  let result = '';
  for (let i = 0; i < length; i++) {
    const j = Math.floor(Math.random() * alphabet.length);
    const c = alphabet.substr(j, 1);
    result += c;
  }
  return result;
}

async function getProjectRandomnessAsync(projectRoot: string) {
  const { urlRandomness: randomness } = await ProjectSettings.readAsync(projectRoot);
  if (randomness) {
    return randomness;
  }
  return await resetProjectRandomnessAsync(projectRoot);
}

async function resetProjectRandomnessAsync(projectRoot: string) {
  const randomness = [randomIdentifier(2), randomIdentifier(3)].join('-');
  await ProjectSettings.setAsync(projectRoot, { urlRandomness: randomness });
  return randomness;
}

async function connectToNgrokAsync(
  projectRoot: string,
  ngrok: any,
  args: NgrokOptions,
  hostnameAsync: () => Promise<string>,
  ngrokPid: number | null | undefined,
  attempts: number = 0
): Promise<string> {
  try {
    const configPath = getNgrokConfigPath();
    const hostname = await hostnameAsync();
    const url = await ngrok.connect({
      hostname,
      configPath,
      onStatusChange: handleStatusChange.bind(null),
      ...args,
    });
    return url;
  } catch (e: any) {
    // Attempt to connect 3 times
    if (attempts >= 2) {
      if (e.message) {
        throw new CommandError('NGROK_ERROR', e.toString());
      } else {
        throw new CommandError('NGROK_ERROR', JSON.stringify(e));
      }
    }
    if (!attempts) {
      attempts = 0;
    } // Attempt to fix the issue
    if (e.error_code && e.error_code === 103) {
      if (attempts === 0) {
        // Failed to start tunnel. Might be because url already bound to another session.
        if (ngrokPid) {
          try {
            process.kill(ngrokPid, 'SIGKILL');
          } catch (e) {
            Log.debug(`Couldn't kill ngrok with PID ${ngrokPid}`);
          }
        } else {
          await ngrok.kill();
        }
      } else {
        // Change randomness to avoid conflict if killing ngrok didn't help
        await resetProjectRandomnessAsync(projectRoot);
      }
    } // Wait 100ms and then try again
    await delayAsync(100);
    return connectToNgrokAsync(projectRoot, ngrok, args, hostnameAsync, null, attempts + 1);
  }
}

export async function startTunnelAsync(
  projectRoot: string,
  options: { autoInstall?: boolean } = {}
): Promise<void> {
  const ngrok = await resolveNgrokAsync(projectRoot, options);
  // TODO: Maybe assert no robot users?
  const username = getActorDisplayName(await getUserAsync());
  const devServerPort = getNativeDevServerPort();
  if (!devServerPort) {
    throw new CommandError(
      'NO_DEV_SERVER',
      `No Metro dev server found for project at: ${projectRoot}`
    );
  }
  await stopTunnelAsync(projectRoot);
  if (await startAdbReverseAsync()) {
    Log.log(
      'Successfully ran `adb reverse`. Localhost URLs should work on the connected Android device.'
    );
  }
  const packageShortName = path.parse(projectRoot).base;

  let startedTunnelsSuccessfully = false;

  // Some issues with ngrok cause it to hang indefinitely. After
  // TUNNEL_TIMEOUTms we just throw an error.
  await Promise.race([
    (async () => {
      await delayAsync(TUNNEL_TIMEOUT);
      if (!startedTunnelsSuccessfully) {
        throw new Error('Starting tunnels timed out');
      }
    })(),

    (async () => {
      const createResolver = (extra: string[] = []) =>
        async function resolveHostnameAsync() {
          const randomness = await getProjectRandomnessAsync(projectRoot);
          return [
            ...extra,
            randomness,
            slugify(username),
            slugify(packageShortName),
            NGROK_CONFIG.domain,
          ].join('.');
        };

      // Custom dev server will share the port across expo and metro dev servers,
      // this means we only need one ngrok URL.
      const serverUrl = await connectToNgrokAsync(
        projectRoot,
        ngrok,
        {
          authtoken: NGROK_CONFIG.authToken,
          port: devServerPort,
          proto: 'http',
        },
        createResolver(),
        NgrokServer.getNgrokInfo()?.pid
      );

      NgrokServer.setNgrokInfo({
        url: serverUrl,
        pid: ngrok.getActiveProcess().pid,
      });

      startedTunnelsSuccessfully = true;

      Log.log('Tunnel ready.');
    })(),
  ]);
}

export async function stopTunnelAsync(projectRoot: string): Promise<void> {
  const ngrok = await resolveNgrokAsync(projectRoot, { shouldPrompt: false }).catch(() => null);
  if (!ngrok) {
    return;
  }

  // This will kill all ngrok tunnels in the process.
  // We'll need to change this if we ever support more than one project
  // open at a time in XDE.
  const ngrokPid = NgrokServer.getNgrokInfo()?.pid;
  const ngrokProcess = ngrok.getActiveProcess();
  const ngrokProcessPid = ngrokProcess ? ngrokProcess.pid : null;
  if (ngrokPid && ngrokPid !== ngrokProcessPid) {
    // Ngrok is running in some other process. Kill at the os level.
    try {
      process.kill(ngrokPid);
    } catch (e) {
      Log.debug(`Couldn't kill ngrok with PID ${ngrokPid}`);
    }
  } else {
    // Ngrok is running from the current process. Kill using ngrok api.
    await ngrok.kill();
  }
  NgrokServer.setNgrokInfo(null);
  // TODO: Just use exit hooks...
  await stopAdbReverseAsync();
}

function handleStatusChange(status: string) {
  if (status === 'closed') {
    Log.error(
      'We noticed your tunnel is having issues. ' +
        'This may be due to intermittent problems with our tunnel provider. ' +
        'If you have trouble connecting to your app, try to Restart the project, ' +
        'or switch Host to LAN.'
    );
  } else if (status === 'connected') {
    Log.log('Tunnel connected.');
  }
}
