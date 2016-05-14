'use strict';

import { config as serverConfig } from 'modern-mean-users-server/dist/server/config/config';

let clientConfig = {
  constants: {
    MODULES: serverConfig.modules,
    SOCIAL: {
      facebook: {
        enable: serverConfig.social.facebook.enable,
        callback: serverConfig.social.facebook.callback
      },
      twitter: {
        enable: serverConfig.social.facebook.enable,
        callback: serverConfig.social.twitter.callback
      },
      google: {
        enable: serverConfig.social.facebook.enable,
        callback: serverConfig.social.google.callback
      },
      linkedin: {
        enable: serverConfig.social.facebook.enable,
        callback: serverConfig.social.google.callback
      },
      github: {
        enable: serverConfig.social.facebook.enable,
        callback: serverConfig.social.google.callback
      },
    }
  },
  values: {
    UPLOAD: serverConfig.uploads,
  }
};

export { clientConfig };
