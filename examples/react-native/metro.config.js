const path = require('path');

const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

/**
 * Metro configuration
 * https://reactnative.dev/docs/metro
 *
 * @type {import('@react-native/metro-config').MetroConfig}
 */
// Metro only resolves files under the project root or a watch folder, and two things this app
// needs live outside it: the binding itself, linked from source
// (`file:../../bindings/react-native`), and the BIP-39 wordlist the SDK demo draws its 12 words
// from, shared with the Android and iOS examples so there is exactly one copy of it.
const config = {
  watchFolders: [
    path.resolve(__dirname, '../../bindings/react-native'),
    path.resolve(__dirname, '../shared'),
  ],
  resolver: {
    // The binding's own imports (`@babel/runtime`, `react-native`) resolve against this app's
    // node_modules rather than its own, so the app and the binding it consumes cannot end up
    // with two copies of React Native loaded at once.
    nodeModulesPaths: [path.resolve(__dirname, 'node_modules')],
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
