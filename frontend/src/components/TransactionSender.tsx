import React, { useState } from 'react';
import { userSession } from '../lib/stacks-auth';
import { openContractCall } from '@stacks/connect';

export const TransactionSender = () => {
    const handleSend = () => {
        // Logic
    };

    return (
        <div>
            <h3>Send Transaction</h3>
            <button onClick={handleSend}>Send</button>
        </div>
    );
};
