<?php
    // ... (previous code remains the same until DKIM section in the results display)
    ?>
    <!-- Replace the DKIM section with this: -->
    <!-- DKIM -->
    <div class="border rounded-lg p-4 bg-gray-50">
        <h3 class="font-bold text-lg mb-2">DKIM (DomainKeys Identified Mail)</h3>
        <div class="space-y-2">
            <p>
                <span class="font-semibold">Status:</span>
                <span class="<?php echo getStatusColor($results['dkim']['status']); ?> font-bold">
                    <?php echo htmlspecialchars(strtoupper($results['dkim']['status'])); ?>
                </span>
            </p>
            <?php if ($results['dkim']['status'] === 'good'): ?>
                <p>
                    <span class="font-semibold">Selector:</span>
                    <?php echo htmlspecialchars($results['dkim']['selector']); ?>
                </p>
                <p class="font-mono text-sm bg-gray-100 p-2 rounded record-box">
                    <?php echo htmlspecialchars($results['dkim']['record']); ?>
                </p>
            <?php else: ?>
                <p><?php echo htmlspecialchars($results['dkim']['message']); ?></p>
            <?php endif; ?>
        </div>
    </div>
    <!-- ... (rest of the code remains the same) -->
