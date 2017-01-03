// @flow
import assert from 'assert';
import nullthrows from 'nullthrows';
import pcap from 'pcap';

import MacAddresses from './MacAddresses';
import NetworkInterfaces from './NetworkInterfaces';
import Packets from './Packets';

/**
 * Configuration options used when creating new {@link DashButton} objects
 */
export type DashButtonOptions = {
  /**
   * Name of the network interface on which to listen, like "en0" or "wlan0".
   * See `ifconfig` for the list of interfaces on your computer. Defaults to the
   * first external interface.
   */
  networkInterface?: string,
};

/**
 * A listener function that a {@link DashButton} object invokes when it detects
 * a press from a Dash button. A listener may be an async function.
 */
export type DashButtonListener = (packet: Object) => void | Promise<void>;

type GuardedListener = (packet: Object) => Promise<?Error>;

let pcapSession;

function getPcapSession(interfaceName: string) {
  if (!pcapSession) {
    pcapSession = Packets.createCaptureSession(interfaceName);
  } else {
    assert.equal(
      interfaceName, pcapSession.device_name,
      'The existing pcap session must be listening on the specified interface',
    );
  }
  return pcapSession;
}

/**
 * A `DashButton` listens to presses from a single Dash button with a specified
 * MAC address. See the setup instructions for how to learn your Dash button's
 * MAC address by scanning for DHCP requests and ARP probes.
 */
export default class DashButton {
  _macAddress: string;
  _networkInterface: string;
  _packetListener: Function;
  _dashListeners: Set<GuardedListener>;
  _isResponding: boolean;

  /**
   * Creates a new `DashButton` object that listens to presses from the Dash
   * button with the given MAC address.
   *
   * @param macAddress MAC address of the physical Dash button
   * @param options optional way to configure the new object
   */
  constructor(macAddress: string, options: DashButtonOptions = {}) {
    this._macAddress = macAddress;
    this._networkInterface = options.networkInterface ||
      nullthrows(NetworkInterfaces.getDefault());
    this._packetListener = this._handlePacket.bind(this);
    this._dashListeners = new Set();
    this._isResponding = false;
  }

  /**
   * Adds a listener function that is invoked when this `DashButton` detects a
   * press from your Dash button. Use the returned subscription to remove the
   * listener.
   *
   * **The listener may be an async function.** If you add an async listener,
   * this `DashButton` will ignore subsequent presses from your Dash button
   * until the async function completes. When you have multiple async listeners,
   * the `DashButton` will wait for all of them to complete, even if some throw
   * errors, before listening to any new presses. This lets you conveniently
   * implement your own policy for throttling presses.
   *
   * @param listener function to invoke when the Dash button is pressed
   * @returns subscription used to remove the listener
   */
  addListener(listener: DashButtonListener): Subscription {
    if (!this._dashListeners.size) {
      let session = getPcapSession(this._networkInterface);
      session.addListener('packet', this._packetListener);
    }

    // We run the listeners with Promise.all, which rejects early as soon as
    // any of its promises are rejected. Since we want to wait for all of the
    // listeners to finish we need to catch any errors they may throw.
    let guardedListener = this._createGuardedListener(listener);
    this._dashListeners.add(guardedListener);

    return new Subscription(() => {
      this._dashListeners.delete(guardedListener);
      if (!this._dashListeners.size) {
        let session = getPcapSession(this._networkInterface);
        session.removeListener('packet', this._packetListener);
        if (!session.listenerCount('packet')) {
          session.close();
        }
      }
    });
  }

  _createGuardedListener(
    listener: (...args: *[]) => void | Promise<void>,
  ): GuardedListener {
    return async (...args: *[]): Promise<?Error> => {
      try {
        await listener(...args);
      } catch (error) {
        return error;
      }
    };
  }

  async _handlePacket(rawPacket: Object): Promise<void> {
    if (this._isResponding) {
      return;
    }

    let packet = pcap.decode(rawPacket);
    let macAddress = MacAddresses.getEthernetSource(packet);
    if (macAddress !== this._macAddress) {
      return;
    }

    this._isResponding = true;
    try {
      // The listeners are guarded so this should never throw, but wrap it in
      // try-catch to be defensive
      let listeners = Array.from(this._dashListeners);
      let errors = await Promise.all(
        listeners.map(listener => listener(packet)),
      );
      for (let error of errors) {
        if (error) {
          // TODO: Figure out how to mock `console` with Jest
          // console.error(`Listener threw an uncaught error:\n${error.stack}`);
        }
      }
    } finally {
      this._isResponding = false;
    }
  }
}

/**
 * Subscriptions are returned from {@link DashButton#addListener} and give you a
 * convenient way to remove listeners.
 */
class Subscription {
  _remove: () => void;

  constructor(onRemove: () => void) {
    this._remove = onRemove;
  }

  /**
   * Removes the listener that is subscribed to the `DashButton`. It will
   * release its reference to the listener's closure to mitigate memory leaks.
   * Calling `remove()` more than once on the same subscription is OK.
   */
  remove(): void {
    if (!this._remove) {
      return;
    }
    this._remove();
    delete this._remove;
  }
}
