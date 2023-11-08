export default {
  changepass: {
    post: {
      summary: 'Change the password of a user',
      description: 'Can be used with or without authentication. If authenticated, an email/password combination will be acepted. If unauthenticated, a valid reset token and password must be specified.',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                email: { type: 'string' },
                password: { type: 'string' },
                token: { type: 'string' }
              }
            }
          }
        }
      },
      responses: { 204: {} }
    }
  },
  forgotpass: {
    post: {
      summary: 'Trigger a password reset',
      description: 'Generates a password reset and emails this to the user with instructions on updating their password.',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                email: { type: 'string' }
              }
            }
          }
        }
      },
      responses: {
        200: {
          content: {
            'application/json': {
              schema: {
                $schema: 'https://json-schema.org/draft/2020-12/schema',
                type: 'object',
                properties: {
                  message: { type: 'string' }
                }
              }
            }
          }
        }
      }
    }
  },
  invite: {
    post: {
      summary: 'Invite a new user',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                email: { type: 'string' }
              }
            }
          }
        }
      },
      responses: { 204: {} }
    }
  },
  register: {
    post: {
      summary: 'Register a new user',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                email: { type: 'string', required: true },
                firstName: { type: 'string', required: true },
                lastName: { type: 'string', required: true },
                password: { type: 'string', required: true },
                roles: {
                  type: 'array',
                  items: { type: 'string' }
                }
              }
            }
          }
        }
      },
      responses: {
        200: {
          content: {
            'application/json': {
              schema: { $ref: '#components/schemas/localauthuser' }
            }
          }
        }
      }
    }
  },
  registersuper: {
    post: {
      summary: 'Register a new super user',
      description: 'Only one user can be registered in this way, and if a super user already exists the request will fail.',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                email: { type: 'string', required: true },
                password: { type: 'string', required: true }
              }
            }
          }
        }
      },
      responses: {
        200: {
          content: {
            'application/json': {
              schema: { $ref: '#components/schemas/localauthuser' }
            }
          }
        }
      }
    }
  },
  root: {
    post: {
      summary: 'Authenticate with the API',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                email: { type: 'string', required: true },
                password: { type: 'string', required: true },
                persistSession: { type: 'boolean' }
              }
            }
          }
        }
      },
      responses: { 204: {} }
    }
  },
  validatepass: {
    post: {
      summary: 'Validate password',
      description: 'Checks that a password passes the required complexity specified in the application's configuration settings.',
      requestBody: {
        content: {
          'application/json': {
            schema: {
              $schema: 'https://json-schema.org/draft/2020-12/schema',
              type: 'object',
              properties: {
                password: { type: 'string', required: true }
              }
            }
          }
        }
      },
      responses: {
        200: {
          content: {
            'application/json': {
              schema: {
                $schema: 'https://json-schema.org/draft/2020-12/schema',
                type: 'object',
                properties: {
                  message: { type: 'string' }
                }
              }
            }
          }
        }
      }
    }
  }
}
