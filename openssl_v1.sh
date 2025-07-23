#!/bin/bash

# temp directory to hold certs pulled down
TMPDIR=$(mktemp -d)
PORT=587

# this says that on any "EXIT" signal, we'll go and delete that directory.
# (this is actually pretty cool)
trap "rm -rf '$TMPDIR'" EXIT

# open file
cat info_certs.json | jq -c '.[]' | while read -r item; do
    # get the data out of info_certs.json
    displayName=$(echo "$item" | jq -r '.displayName')
    hostURL=$(echo "$item" | jq -r '.hostURL')
    localFileName=$(echo "$item" | jq -r '.localFileName')
    lastChecked=$(echo "$item" | jq -r '.lastChecked')
    echo ""
    echo "== Verifying certificates for: $displayName... =="

    # check expiry
    expiry_date=$(openssl x509 -enddate -noout -in $localFileName | cut -d= -f2 | tr -d '/r' | awk '{print $1, $2, $3, $4, $5}')
    echo "This certificate will expire on: [$expiry_date]"
    expiry_epoch=$(date -d "$expiry_date" +%s)
    now_epoch=$(date +%s) #1832673000
    CONST_SIX_MONTHS=$((6 * 30 * 24 * 60 * 60))

    if (( expiry_epoch - now_epoch <= CONST_SIX_MONTHS )); then
        echo "⚠️ Hey! This certificate is gonna expire soon. Heads up!"
        echo "⚠️ Expires on: $expiry_date"
    fi

    # print out
    echo "Connecting to $hostURL on port $PORT..."
    echo -n | \
    # initiate the connection - and put all the data
    # into raw_output.txt. this however does contain
    # some info we don't need.
    openssl s_client -starttls smtp \
        -connect "${hostURL}:${PORT}" \
        -showcerts > "$TMPDIR/raw_output.txt"
    # strip out all that useless data and just keep the
    # raw certs. put that into certs.pem.
    awk '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/' "$TMPDIR/raw_output.txt" > "$TMPDIR/certs.pem"

    # now we've got all the certs in one file
    # but we need them in separate ones
    echo "Certificates received. Splitting..."
    csplit -s -z -f "$TMPDIR/cert" -b "%02d.cer" "$TMPDIR/certs.pem" '/-----BEGIN CERTIFICATE-----/' '{*}'

    CERT_FILES=($TMPDIR/cert*.cer)
    CERT_COUNT=${#CERT_FILES[@]}
    echo "number of certificates recieved: $CERT_COUNT"
    LEAF_CERT="${CERT_FILES[0]}"
    ROOT_CERT="${CERT_FILES[-1]}"
    INTERMEDIATES=("${CERT_FILES[@]:1:$((CERT_COUNT))}")

    # ssl verify expects the whole chain (except the leaf) in the -untrusted.
    # so now that we've split them all apart, we need to send the intermediate
    # certs into one file
    echo "combining.."
    if [ "${#INTERMEDIATES[@]}" -gt 0 ]; then
        # add these to intermediates - in the correct order
        touch "$TMPDIR/intermediates.pem"
        for (( i=1; i < $CERT_COUNT; i++)); do
            cat "$TMPDIR/cert0$i.cer" >> "$TMPDIR/intermediates.pem"
        done
    else
        # No intermediates, create an empty file
        echo "No immediates found. Potential errors below..."
        > "$TMPDIR/intermediates.pem"
    fi

    # this test will work its way down the chain
    echo "-- BIG GIANT TEST --"
    openssl verify -x509_strict -CAfile "$localFileName" -untrusted "$TMPDIR/intermediates.pem" "$LEAF_CERT"
    if [ $? -ne 0 ]; then
        echo "❌ Certificate verification failed!"
        echo "❌ Expected issuer:"
        echo "$displayName" >> "$FAILS_FILE"
        openssl x509 -issuer -noout -in "$TMPDIR/cert0$(($CERT_COUNT-1)).cer"
    else
        echo "✅ Certificate verified successfully."
    fi

    # these tests will individually go through each of the certs
    # and verify that each is the signer of the next
    echo "-- INDIVIDUAL TESTS --"
    echo "verifying cert0$(($CERT_COUNT-1)) (top level cert)..."
    openssl verify -x509_strict -CAfile "$localFileName" "$TMPDIR/cert0$(($CERT_COUNT-1)).cer"
    if [ $? -ne 0 ]; then
        echo "❌ Certificate verification failed! (this should only happen if the big giant test also failed.)"
    else
        echo "✅ Certificate verified successfully."
    fi
    for ((i=$CERT_COUNT-2; i >= 0; i--)); do
        echo "verifying cert0$i..."
        openssl verify -x509_strict -untrusted "$TMPDIR/cert0$(($i+1)).cer" "$TMPDIR/cert0$i.cer"
        if [ $? -ne 0 ]; then
            echo "❌ Certificate verification failed! The certificates that were sent are not correct. This is an issue from $displayName."
        else
            echo "✅ Certificate verified successfully."
        fi
    done

    # we're done now - so delete all the files we just made in the temp directory
    # so we can move to the next cert.
    echo "Certificate chain verified successfully."
    rm $TMPDIR/*
done